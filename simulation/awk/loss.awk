# Packet Loss Ratio Calculation for NS-2 Trace File
# Loss Ratio (%) = (Total Packets Dropped 'd' / Total Packets Sent '+') * 100
BEGIN {
    sent = 0;
    dropped = 0;
}
{
    event = $1;
    if (event == "+") {
        sent++;
    }
    if (event == "d") {
        dropped++;
    }
}
END {
    if (sent > 0) {
        loss_ratio = (dropped / sent) * 100;
        printf("Total Packets Sent (+): %d\n", sent);
        printf("Total Packets Dropped (d): %d\n", dropped);
        printf("Packet Loss Ratio: %.2f %%\n", loss_ratio);
    } else {
        printf("Packet Loss Ratio: 0.00 %%\n");
    }
}
