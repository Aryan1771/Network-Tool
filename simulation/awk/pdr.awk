# Packet Delivery Ratio (PDR) Calculation for NS-2 Trace File
# PDR (%) = (Total Packets Received / Total Packets Sent) * 100
BEGIN {
    sent = 0;
    received = 0;
}
{
    event = $1;
    if (event == "+") {
        sent++;
    }
    if (event == "r") {
        received++;
    }
}
END {
    if (sent > 0) {
        pdr = (received / sent) * 100;
        printf("Total Packets Generated (+): %d\n", sent);
        printf("Total Packets Delivered (r): %d\n", received);
        printf("Packet Delivery Ratio (PDR): %.2f %%\n", pdr);
    } else {
        printf("Packet Delivery Ratio (PDR): 0.00 %%\n");
    }
}
