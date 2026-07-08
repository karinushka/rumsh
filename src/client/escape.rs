/// Local escape commands that can be executed on the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeCommand {
    /// Terminate connection gracefully (~.)
    Disconnect,
    /// Suspend client process (~^Z)
    Suspend,
    /// Display help overlay (~?)
    Help,
    /// Toggle latency/loss overlay (~o)
    ToggleOverlay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeState {
    /// Normal typing state. We track if the last character was a newline to know if we can trigger.
    Normal { last_was_newline: bool },
    /// We saw a newline followed by `~`. We are holding the `~` and waiting for the next character.
    WaitingForCommand,
}

/// A state machine that intercepts SSH-like escape sequences from the stdin stream.
pub struct EscapeInterpreter {
    state: EscapeState,
}

pub enum InterpreterResult {
    /// Send these raw bytes to the server.
    SendBytes(Vec<u8>),
    /// Execute a local command.
    Command(EscapeCommand),
    /// Consume the byte and wait (holding the tilde).
    Consume,
}

impl Default for EscapeInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl EscapeInterpreter {
    pub fn new() -> Self {
        Self {
            state: EscapeState::Normal {
                last_was_newline: true,
            }, // Start of session acts as a newline
        }
    }

    /// Feeds a single byte into the state machine, returning what action to take.
    pub fn handle_byte(&mut self, b: u8) -> InterpreterResult {
        match self.state {
            EscapeState::Normal { last_was_newline } => {
                if last_was_newline && b == b'~' {
                    self.state = EscapeState::WaitingForCommand;
                    InterpreterResult::Consume
                } else {
                    let is_nl = b == b'\r' || b == b'\n';
                    self.state = EscapeState::Normal {
                        last_was_newline: is_nl,
                    };
                    InterpreterResult::SendBytes(vec![b])
                }
            }
            EscapeState::WaitingForCommand => {
                match b {
                    b'.' => {
                        self.state = EscapeState::Normal {
                            last_was_newline: false,
                        };
                        InterpreterResult::Command(EscapeCommand::Disconnect)
                    }
                    0x1a => {
                        // Ctrl-Z (SUB)
                        self.state = EscapeState::Normal {
                            last_was_newline: true,
                        };
                        InterpreterResult::Command(EscapeCommand::Suspend)
                    }
                    b'?' => {
                        self.state = EscapeState::Normal {
                            last_was_newline: false,
                        };
                        InterpreterResult::Command(EscapeCommand::Help)
                    }
                    b'o' => {
                        self.state = EscapeState::Normal {
                            last_was_newline: false,
                        };
                        InterpreterResult::Command(EscapeCommand::ToggleOverlay)
                    }
                    b'~' => {
                        // Typing tilde twice sends a single literal tilde
                        self.state = EscapeState::Normal {
                            last_was_newline: false,
                        };
                        InterpreterResult::SendBytes(vec![b'~'])
                    }
                    _ => {
                        // Abort! The sequence is not a command. Send the buffered tilde and this character.
                        let is_nl = b == b'\r' || b == b'\n';
                        self.state = EscapeState::Normal {
                            last_was_newline: is_nl,
                        };
                        InterpreterResult::SendBytes(vec![b'~', b])
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_typing() {
        let mut interpreter = EscapeInterpreter::new();

        // Typing 'abc' at the start (even though start acts as newline, 'a' is not tilde)
        assert!(
            matches!(interpreter.handle_byte(b'a'), InterpreterResult::SendBytes(bs) if bs == vec![b'a'])
        );
        assert!(
            matches!(interpreter.handle_byte(b'b'), InterpreterResult::SendBytes(bs) if bs == vec![b'b'])
        );

        // Typing '~/a' in the middle of a line (tilde is not after a newline, so it is sent immediately)
        assert!(
            matches!(interpreter.handle_byte(b'~'), InterpreterResult::SendBytes(bs) if bs == vec![b'~'])
        );
        assert!(
            matches!(interpreter.handle_byte(b'a'), InterpreterResult::SendBytes(bs) if bs == vec![b'a'])
        );
    }

    #[test]
    fn test_escape_trigger_and_disconnect() {
        let mut interpreter = EscapeInterpreter::new();

        // 1. Tilde at the very start (start of session acts as newline) -> Consumed
        assert!(matches!(
            interpreter.handle_byte(b'~'),
            InterpreterResult::Consume
        ));

        // 2. Followed by '.' -> Disconnect command
        assert!(matches!(
            interpreter.handle_byte(b'.'),
            InterpreterResult::Command(EscapeCommand::Disconnect)
        ));
    }

    #[test]
    fn test_escape_after_newline() {
        let mut interpreter = EscapeInterpreter::new();

        // Type some characters
        let _ = interpreter.handle_byte(b'a');

        // Type tilde in middle -> sent immediately
        assert!(
            matches!(interpreter.handle_byte(b'~'), InterpreterResult::SendBytes(bs) if bs == vec![b'~'])
        );

        // Press Enter (\n)
        let _ = interpreter.handle_byte(b'\n');

        // Type tilde immediately after Enter -> Consumed
        assert!(matches!(
            interpreter.handle_byte(b'~'),
            InterpreterResult::Consume
        ));

        // Followed by 'o' -> ToggleOverlay command
        assert!(matches!(
            interpreter.handle_byte(b'o'),
            InterpreterResult::Command(EscapeCommand::ToggleOverlay)
        ));
    }

    #[test]
    fn test_double_tilde() {
        let mut interpreter = EscapeInterpreter::new();

        // Tilde at start -> Consumed
        assert!(matches!(
            interpreter.handle_byte(b'~'),
            InterpreterResult::Consume
        ));

        // Tilde again -> sends a single tilde
        assert!(
            matches!(interpreter.handle_byte(b'~'), InterpreterResult::SendBytes(bs) if bs == vec![b'~'])
        );

        // Third tilde immediately after is NOT at start of line anymore (the previous double-tilde resolved it)
        // So the third tilde should be sent immediately!
        assert!(
            matches!(interpreter.handle_byte(b'~'), InterpreterResult::SendBytes(bs) if bs == vec![b'~'])
        );
    }

    #[test]
    fn test_aborted_escape_sequence() {
        let mut interpreter = EscapeInterpreter::new();

        // Tilde at start -> Consumed
        assert!(matches!(
            interpreter.handle_byte(b'~'),
            InterpreterResult::Consume
        ));

        // Followed by 'a' (not a command) -> Aborts, sending both '~' and 'a'
        assert!(
            matches!(interpreter.handle_byte(b'a'), InterpreterResult::SendBytes(bs) if bs == vec![b'~', b'a'])
        );
    }
}
