# ==============================================================================
# JIIT Computer Networks Lab (24B15CS313)
# Scenario 1: Baseline Normal Network Traffic Simulation
# Architecture: 4 Nodes (Client n0, Router n1, Switch n2, Server n3)
# ==============================================================================

set ns [new Simulator]

# Define visualization colors for NAM
$ns color 1 Blue
$ns color 2 Green

# Open trace and nam files
set tracefile [open normal_traffic.tr w]
$ns trace-all $tracefile

set namfile [open normal_traffic.nam w]
$ns namtrace-all $namfile

# Finish procedure
proc finish {} {
    global ns tracefile namfile
    $ns flush-trace
    close $tracefile
    close $namfile
    puts "Normal Traffic Simulation Completed. Output saved to normal_traffic.tr and normal_traffic.nam"
    exit 0
}

# Create 4 Nodes
set n0 [$ns node]
set n1 [$ns node]
set n2 [$ns node]
set n3 [$ns node]

# Label nodes for NAM
$n0 label "Client (n0)"
$n1 label "Gateway (n1)"
$n2 label "Core Router (n2)"
$n3 label "Server (n3)"

# Establish Duplex Links: Node1 Node2 Bandwidth Delay QueueType
$ns duplex-link $n0 $n1 10Mb 10ms DropTail
$ns duplex-link $n1 $n2 10Mb 20ms DropTail
$ns duplex-link $n2 $n3 10Mb 10ms DropTail

# Set Queue Limit
$ns queue-limit $n1 $n2 20

# Setup TCP Agent on n0 and TCPSink on n3 (FTP Traffic)
set tcp [new Agent/TCP]
$tcp set class_ 1
$ns attach-agent $n0 $tcp
set sink [new Agent/TCPSink]
$ns attach-agent $n3 $sink
$ns connect $tcp $sink
$tcp set fid_ 1

# Setup FTP application over TCP
set ftp [new Application/FTP]
$ftp attach-agent $tcp
$ftp set type_ FTP

# Setup UDP CBR Traffic on n1 -> n3 (Background Traffic)
set udp [new Agent/UDP]
$ns attach-agent $n1 $udp
set null [new Agent/Null]
$ns attach-agent $n3 $null
$ns connect $udp $null
$udp set fid_ 2

set cbr [new Application/Traffic/CBR]
$cbr attach-agent $udp
$cbr set type_ CBR
$cbr set packet_size_ 1000
$cbr set rate_ 1Mb
$cbr set random_ false

# Schedule Traffic Events
$ns at 0.5 "$cbr start"
$ns at 1.0 "$ftp start"
$ns at 4.0 "$ftp stop"
$ns at 4.5 "$cbr stop"
$ns at 5.0 "finish"

# Run Simulation
$ns run
