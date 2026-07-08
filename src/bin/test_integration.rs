use anyhow::Result;
use rumsh::crypto::CryptoManager;
use rumsh::protocol::{
    ClientPayload, EncryptedClientPacket, EncryptedServerPacket, ServerPayload, deserialize,
    deserialize_compressed, serialize,
};
use std::net::UdpSocket;
use std::process::Command;
use std::time::Duration;

fn main() -> Result<()> {
    let port = 45000;
    let key_bytes = [0u8; 32];
    let key_hex = key_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    println!("Spawning rumsh server on port {}...", port);
    let log_file = std::fs::File::create("target/server.log")?;
    let mut server_child = Command::new("target/debug/rumsh")
        .arg("server")
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--shell")
        .arg("/bin/bash -i")
        .env("RUMSH_KEY", &key_hex)
        .env("RUST_LOG", "trace")
        .stderr(std::process::Stdio::from(log_file))
        .spawn()?;

    // Wait for server to bind
    std::thread::sleep(Duration::from_millis(500));

    println!("Connecting UDP socket...");
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(1000)))?;
    let server_addr = format!("127.0.0.1:{}", port);

    let crypto_handshake = CryptoManager::new(&key_bytes, 0);

    // 1. Send Handshake
    println!("Sending Handshake...");
    let handshake_payload = ClientPayload::Handshake {
        client_version: 1,
        cols: 80,
        rows: 24,
    };
    let payload_bytes = serialize(&handshake_payload)?;
    let ciphertext = crypto_handshake.encrypt(1, &payload_bytes)?;
    let packet = EncryptedClientPacket {
        session_id: 0,
        seq_num: 1,
        ack_seq_num: 0,
        ciphertext,
    };
    socket.send_to(&serialize(&packet)?, &server_addr)?;

    // 2. Read HandshakeAck
    let mut buf = [0u8; 65535];
    let (n, _) = socket.recv_from(&mut buf)?;
    let server_packet = deserialize::<EncryptedServerPacket>(&buf[..n])?;
    let payload_bytes =
        crypto_handshake.decrypt(server_packet.seq_num, &server_packet.ciphertext)?;
    let session_id = match deserialize::<ServerPayload>(&payload_bytes)? {
        ServerPayload::HandshakeAck { session_id } => {
            println!("Handshake successful! Session ID: {}", session_id);
            session_id
        }
        other => {
            return Err(anyhow::anyhow!("Expected HandshakeAck, got {:?}", other));
        }
    };

    let crypto_session = CryptoManager::new(&key_bytes, session_id);

    // 3. Read initial frame
    println!("Waiting for initial frame...");
    let (n, _) = socket.recv_from(&mut buf)?;
    let server_packet = deserialize::<EncryptedServerPacket>(&buf[..n])?;
    let payload_bytes = crypto_session.decrypt(server_packet.seq_num, &server_packet.ciphertext)?;
    match deserialize_compressed::<ServerPayload>(&payload_bytes)? {
        ServerPayload::Frame(update) => {
            println!(
                "Received initial frame update: cols={}, rows={}",
                update.cols, update.rows
            );
            for row in &update.row_updates {
                let text: String = row
                    .cells
                    .iter()
                    .map(|c| c.cell.graphemes.as_str())
                    .collect();
                println!("  Row {}: {:?}", row.y, text);
            }
        }
        other => {
            println!("Expected Frame, got {:?}", other);
        }
    }

    // 4. Send resize request (80x24 -> 90x30)
    println!("Sending Resize request (90x30)...");
    let resize_payload = ClientPayload::Resize { cols: 90, rows: 30 };
    let resize_bytes = serialize(&resize_payload)?;
    let ciphertext = crypto_session.encrypt(2, &resize_bytes)?;
    let packet = EncryptedClientPacket {
        session_id,
        seq_num: 2,
        ack_seq_num: server_packet.seq_num,
        ciphertext,
    };
    socket.send_to(&serialize(&packet)?, &server_addr)?;

    // 5. Wait for server's frame sync response
    println!("Waiting for frame sync response...");
    match socket.recv_from(&mut buf) {
        Ok((n, _)) => {
            let server_packet = deserialize::<EncryptedServerPacket>(&buf[..n])?;
            let payload_bytes =
                crypto_session.decrypt(server_packet.seq_num, &server_packet.ciphertext)?;
            match deserialize_compressed::<ServerPayload>(&payload_bytes)? {
                ServerPayload::Frame(update) => {
                    println!(
                        "Received frame update after resize: cols={}, rows={}",
                        update.cols, update.rows
                    );
                }
                other => {
                    println!("Got other packet: {:?}", other);
                }
            }
        }
        Err(e) => {
            println!("Timed out waiting for frame sync: {:?}", e);
        }
    }

    // 6. Send 'hello\n' to generate text on screen
    println!("Sending 'hello\\n' to write text to screen...");
    let keys_payload = ClientPayload::Keystrokes(b"hello\n".to_vec());
    let keys_bytes = serialize(&keys_payload)?;
    let ciphertext = crypto_session.encrypt(3, &keys_bytes)?;
    let packet = EncryptedClientPacket {
        session_id,
        seq_num: 3,
        ack_seq_num: server_packet.seq_num,
        ciphertext,
    };
    socket.send_to(&serialize(&packet)?, &server_addr)?;

    // 7. Wait and drain echo/output response
    println!("Waiting for command output...");
    std::thread::sleep(Duration::from_millis(500));
    let mut last_seq = server_packet.seq_num;
    let mut drain_buf = [0u8; 65535];
    socket.set_nonblocking(true)?;
    while let Ok((n, _)) = socket.recv_from(&mut drain_buf) {
        if let Ok(server_packet) = deserialize::<EncryptedServerPacket>(&drain_buf[..n]) {
            last_seq = server_packet.seq_num;
            if let Ok(payload_bytes) =
                crypto_session.decrypt(server_packet.seq_num, &server_packet.ciphertext)
                && let Ok(ServerPayload::Frame(update)) =
                    deserialize_compressed::<ServerPayload>(&payload_bytes)
            {
                println!(
                    "Received frame update during echo (seq={}):",
                    server_packet.seq_num
                );
                for row in &update.row_updates {
                    let text: String = row
                        .cells
                        .iter()
                        .map(|c| c.cell.graphemes.as_str())
                        .collect();
                    println!("  Row {}: {:?}", row.y, text);
                }
            }
        }
    }
    socket.set_nonblocking(false)?;

    // 7.2. Start infinite loop to stress PTY output
    println!("Starting infinite loop to stress PTY output...");
    let stress_payload =
        ClientPayload::Keystrokes(b"while true; do echo y; sleep 0.01; done\n".to_vec());
    let ciphertext = crypto_session.encrypt(4, &serialize(&stress_payload)?)?;
    let packet = EncryptedClientPacket {
        session_id,
        seq_num: 4,
        ack_seq_num: last_seq,
        ciphertext,
    };
    socket.send_to(&serialize(&packet)?, &server_addr)?;

    // Let it run for 1 second, draining packets to prevent buffer overflow
    println!("Flooding output for 1 second...");
    let start_flood = std::time::Instant::now();
    socket.set_nonblocking(true)?;
    let mut flood_buf = [0u8; 65535];
    let mut last_seq_stress = last_seq;
    while start_flood.elapsed() < Duration::from_secs(1) {
        if let Ok((n, _)) = socket.recv_from(&mut flood_buf)
            && let Ok(server_packet) = deserialize::<EncryptedServerPacket>(&flood_buf[..n])
        {
            last_seq_stress = server_packet.seq_num;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    socket.set_nonblocking(false)?;

    // Now send Ctrl-C to interrupt
    println!("Sending Ctrl-C to interrupt the loop...");
    let ctrl_c_payload = ClientPayload::Keystrokes(vec![3]); // Ctrl-C is 3
    let ciphertext = crypto_session.encrypt(5, &serialize(&ctrl_c_payload)?)?;
    let packet = EncryptedClientPacket {
        session_id,
        seq_num: 5,
        ack_seq_num: last_seq_stress,
        ciphertext,
    };
    let ctrl_c_sent_at = std::time::Instant::now();
    socket.send_to(&serialize(&packet)?, &server_addr)?;

    // Wait for the prompt to return by draining packets and checking the grid
    println!("Waiting for shell prompt to return...");
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut interrupted = false;
    let mut prompt_latency = Duration::from_secs(0);
    let mut last_seq_after_stress = last_seq_stress;

    let mut drain_buf = [0u8; 65535];
    while ctrl_c_sent_at.elapsed() < Duration::from_secs(2) {
        match socket.recv_from(&mut drain_buf) {
            Ok((n, _)) => {
                let server_packet = deserialize::<EncryptedServerPacket>(&drain_buf[..n])?;
                last_seq_after_stress = server_packet.seq_num;
                if let Ok(payload_bytes) =
                    crypto_session.decrypt(server_packet.seq_num, &server_packet.ciphertext)
                    && let Ok(ServerPayload::Frame(update)) =
                        deserialize_compressed::<ServerPayload>(&payload_bytes)
                {
                    // Check if the prompt (which contains '$') is present in the updates
                    for row in &update.row_updates {
                        let text: String = row
                            .cells
                            .iter()
                            .map(|c| c.cell.graphemes.as_str())
                            .collect();
                        if text.contains('$') {
                            interrupted = true;
                            prompt_latency = ctrl_c_sent_at.elapsed();
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                println!("Error or timeout receiving: {:?}", e);
                break;
            }
        }
        if interrupted {
            break;
        }
    }

    if interrupted {
        println!(
            "PASS: Loop interrupted successfully! Prompt returned in {:?}",
            prompt_latency
        );
    } else {
        let _ = server_child.kill();
        return Err(anyhow::anyhow!(
            "FAIL: Failed to interrupt loop within 2 seconds!"
        ));
    }

    // 7.5 Send Ctrl-L (byte 12)
    println!("Sending Ctrl-L keystroke to clear screen...");
    let ctrl_l_payload = ClientPayload::Keystrokes(vec![12]);
    let ctrl_l_bytes = serialize(&ctrl_l_payload)?;
    let ciphertext = crypto_session.encrypt(6, &ctrl_l_bytes)?; // seq_num 6
    let packet = EncryptedClientPacket {
        session_id,
        seq_num: 6,
        ack_seq_num: last_seq_after_stress,
        ciphertext,
    };
    let send_time = std::time::Instant::now();
    socket.send_to(&serialize(&packet)?, &server_addr)?;

    // Wait for response to Ctrl-L
    println!("Waiting for Ctrl-L clear screen response...");
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let ctrl_l_resp_packet = match socket.recv_from(&mut buf) {
        Ok((n, _)) => {
            let elapsed = send_time.elapsed();
            let server_packet = deserialize::<EncryptedServerPacket>(&buf[..n])?;
            let payload_bytes =
                crypto_session.decrypt(server_packet.seq_num, &server_packet.ciphertext)?;
            match deserialize_compressed::<ServerPayload>(&payload_bytes)? {
                ServerPayload::Frame(update) => {
                    println!("Received frame update for Ctrl-L in {:?}", elapsed);
                    println!(
                        "  Cols={}, Rows={}, Row updates={}",
                        update.cols,
                        update.rows,
                        update.row_updates.len()
                    );
                }
                other => {
                    println!("Got other packet for Ctrl-L: {:?}", other);
                }
            }
            server_packet
        }
        Err(e) => {
            let _ = server_child.kill();
            return Err(anyhow::anyhow!("Timed out waiting for Ctrl-L: {:?}", e));
        }
    };

    // 7.8. Start 'top' to test CPU usage under normal interactive updates
    println!("Starting 'top' to test CPU usage...");
    let top_payload = ClientPayload::Keystrokes(b"top\n".to_vec());
    let ciphertext = crypto_session.encrypt(7, &serialize(&top_payload)?)?; // seq 7
    let packet = EncryptedClientPacket {
        session_id,
        seq_num: 7,
        ack_seq_num: ctrl_l_resp_packet.seq_num,
        ciphertext,
    };
    socket.send_to(&serialize(&packet)?, &server_addr)?;

    // Let it run for 4 seconds, draining packets to prevent buffer overflow
    println!("Running 'top' for 4 seconds...");
    let start_top = std::time::Instant::now();
    socket.set_nonblocking(true)?;
    let mut top_buf = [0u8; 65535];
    let mut last_seq_top = ctrl_l_resp_packet.seq_num;
    let mut measured_cpu = false;
    let mut cpu_readings = Vec::new();

    while start_top.elapsed() < Duration::from_secs(4) {
        if let Ok((n, _)) = socket.recv_from(&mut top_buf)
            && let Ok(server_packet) = deserialize::<EncryptedServerPacket>(&top_buf[..n])
        {
            last_seq_top = server_packet.seq_num;
        }

        // Measure CPU after 2 seconds (to let 'top' settle and send its first updates)
        if start_top.elapsed() > Duration::from_secs(2) && !measured_cpu {
            // Measure CPU a few times to get an average
            if let Ok(cpu) = get_cpu_usage(server_child.id()) {
                cpu_readings.push(cpu);
            }
            if cpu_readings.len() >= 3 {
                measured_cpu = true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    socket.set_nonblocking(false)?;

    let avg_cpu = if !cpu_readings.is_empty() {
        cpu_readings.iter().sum::<f32>() / cpu_readings.len() as f32
    } else {
        0.0
    };
    println!(
        "Measured Server CPU usage while running top: {:.1}%",
        avg_cpu
    );

    // Now send 'q' to exit 'top'
    println!("Sending 'q' to exit 'top'...");
    let q_payload = ClientPayload::Keystrokes(b"q".to_vec());
    let ciphertext = crypto_session.encrypt(8, &serialize(&q_payload)?)?; // seq 8
    let packet = EncryptedClientPacket {
        session_id,
        seq_num: 8,
        ack_seq_num: last_seq_top,
        ciphertext,
    };
    let q_sent_at = std::time::Instant::now();
    socket.send_to(&serialize(&packet)?, &server_addr)?;

    // Wait for the prompt to return by draining packets and checking the grid
    println!("Waiting for shell prompt to return after exiting top...");
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut top_exited = false;
    let mut top_exit_latency = Duration::from_secs(0);
    let mut last_seq_after_top = last_seq_top;

    let mut drain_buf = [0u8; 65535];
    while q_sent_at.elapsed() < Duration::from_secs(2) {
        match socket.recv_from(&mut drain_buf) {
            Ok((n, _)) => {
                if let Ok(server_packet) = deserialize::<EncryptedServerPacket>(&drain_buf[..n]) {
                    last_seq_after_top = server_packet.seq_num;
                    if let Ok(payload_bytes) =
                        crypto_session.decrypt(server_packet.seq_num, &server_packet.ciphertext)
                        && let Ok(ServerPayload::Frame(update)) =
                            deserialize_compressed::<ServerPayload>(&payload_bytes)
                    {
                        // Check if the prompt (which contains '$') is present in the updates
                        for row in &update.row_updates {
                            let text: String = row
                                .cells
                                .iter()
                                .map(|c| c.cell.graphemes.as_str())
                                .collect();
                            if text.contains('$') {
                                top_exited = true;
                                top_exit_latency = q_sent_at.elapsed();
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("Error or timeout receiving: {:?}", e);
                break;
            }
        }
        if top_exited {
            break;
        }
    }

    if top_exited {
        println!(
            "PASS: top exited successfully! Prompt returned in {:?}",
            top_exit_latency
        );
    } else {
        let _ = server_child.kill();
        return Err(anyhow::anyhow!(
            "FAIL: Failed to exit top within 2 seconds!"
        ));
    }

    // 8. Send "\nexit\n" to PTY
    println!("Sending '\\nexit\\n' to trigger shell exit...");
    let exit_payload = ClientPayload::Keystrokes(b"\nexit\n".to_vec());
    let exit_bytes = serialize(&exit_payload)?;
    let ciphertext = crypto_session.encrypt(9, &exit_bytes)?; // seq_num 9
    let packet = EncryptedClientPacket {
        session_id,
        seq_num: 9,
        ack_seq_num: last_seq_after_top,
        ciphertext,
    };
    socket.send_to(&serialize(&packet)?, &server_addr)?;

    // 9. Wait for Shutdown packet from server
    println!("Waiting for Shutdown packet...");
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut shutdown_received = false;
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => {
                let server_packet = deserialize::<EncryptedServerPacket>(&buf[..n])?;
                if let Ok(payload_bytes) =
                    crypto_session.decrypt(server_packet.seq_num, &server_packet.ciphertext)
                {
                    match deserialize_compressed::<ServerPayload>(&payload_bytes)? {
                        ServerPayload::Shutdown => {
                            println!("Successfully received Shutdown packet from server!");
                            shutdown_received = true;
                            break;
                        }
                        other => {
                            println!(
                                "Received other packet while waiting for Shutdown: {:?}",
                                other
                            );
                        }
                    }
                }
            }
            Err(e) => {
                println!("Timed out waiting for Shutdown packet: {:?}", e);
                break;
            }
        }
    }

    if !shutdown_received {
        println!("Error: Did not receive Shutdown packet!");
        let _ = server_child.kill();
        return Err(anyhow::anyhow!("Shutdown packet not received"));
    }

    // 10. Verify server child exited on its own
    println!("Waiting for server process to exit...");
    std::thread::sleep(Duration::from_millis(500));
    match server_child.try_wait()? {
        Some(status) => {
            println!("Server process exited on its own with status: {:?}", status);
        }
        None => {
            println!("Error: Server process is still running after PTY exit!");
            let _ = server_child.kill();
            return Err(anyhow::anyhow!("Server process failed to exit"));
        }
    }

    Ok(())
}

fn get_cpu_usage(pid: u32) -> Result<f32> {
    let output = std::process::Command::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-o")
        .arg("%cpu")
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let lines: Vec<&str> = stdout.lines().collect();
    if lines.len() >= 2 {
        let cpu_str = lines[1].trim();
        let cpu: f32 = cpu_str.parse()?;
        Ok(cpu)
    } else {
        Err(anyhow::anyhow!("Invalid ps output: {}", stdout))
    }
}
