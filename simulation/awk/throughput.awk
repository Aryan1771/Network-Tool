# Throughput Calculation in Kbps for NS-2 Trace File
# Event format: $1=event (+, -, r, d), $2=time, $5=pkt_type, $6=pkt_size, $8=fid
BEGIN {
    received_bytes = 0;
    start_time = 1e9;
    end_time = 0;
}
{
    event = $1;
    time = $2;
    pkt_size = $6;
    
    if (event == "r" || event == "-") {
        if (time < start_time) start_time = time;
        if (time > end_time) end_time = time;
    }
    
    # Count packets received successfully ('r')
    if (event == "r") {
        received_bytes += pkt_size;
    }
}
END {
    duration = end_time - start_time;
    if (duration > 0) {
        throughput_kbps = (received_bytes * 8) / (duration * 1000);
        printf("Simulation Time: %.3f s to %.3f s (Duration: %.3f s)\n", start_time, end_time, duration);
        printf("Total Data Received: %d bytes\n", received_bytes);
        printf("Throughput: %.2f Kbps\n", throughput_kbps);
    } else {
        printf("Throughput: 0.00 Kbps\n");
    }
}
