# Average End-to-End Delay Calculation for NS-2 Trace File
# Matches packet send times ('-' or '+') with packet receive times ('r') by packet_id ($12)
BEGIN {
    total_delay = 0;
    count = 0;
}
{
    event = $1;
    time = $2;
    pkt_id = $12;

    if (event == "+" && send_time[pkt_id] == 0) {
        send_time[pkt_id] = time;
    }
    if (event == "r") {
        if (send_time[pkt_id] > 0) {
            delay = time - send_time[pkt_id];
            total_delay += delay;
            count++;
            delete send_time[pkt_id];
        }
    }
}
END {
    if (count > 0) {
        avg_delay_ms = (total_delay / count) * 1000;
        printf("Packets Measured for Delay: %d\n", count);
        printf("Total Latency: %.4f s\n", total_delay);
        printf("Average End-to-End Delay: %.2f ms\n", avg_delay_ms);
    } else {
        printf("Average End-to-End Delay: 0.00 ms\n");
    }
}
