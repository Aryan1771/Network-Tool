# ==============================================================================
# JIIT Computer Networks Lab (24B15CS313)
# Scenario 3: Packet Loss and Network Degradation Simulation
# Architecture: Source (n0), Lossy Link (n1-n2), Destination (n3)
# ==============================================================================

set ns [new Simulator]

$ns color 1 Magenta
$ns color 2 Cyan

set tracefile [open packet_loss_scenario.tr w]
$ns trace-all $tracefile

set namfile [open packet_loss_scenario.nam w]
$ns namtrace-all $namfile

proc finish {} {
    global ns tracefile namfile
    $ns flush-trace
    close $tracefile
    close $namfile
    puts "Packet Loss Simulation Completed. Output saved to packet_loss_scenario.tr"
    exit 0
}

set n0 [$ns node]
set n1 [$ns node]
set n2 [$ns node]
set n3 [$ns node]

$n0 label "Src (n0)"
$n1 label "Hop 1 (n1)"
$n2 label "Hop 2 (n2)"
$n3 label "Dst (n3)"

$ns duplex-link $n0 $n1 5Mb 10ms DropTail
$ns duplex-link $n1 $n2 1.5Mb 50ms DropTail
$ns duplex-link $n2 $n3 5Mb 10ms DropTail

$ns queue-limit $n1 $n2 15

# Introduce a 10% packet error rate on link n1-n2
set loss_module [new ErrorModel]
$loss_module unit pkt
$loss_module set rate_ 0.12
$loss_module ranvar [new RandomVariable/Uniform]
$loss_module drop-target [new Agent/Null]
$ns lossmodel $loss_module $n1 $n2

# TCP Agent
set tcp [new Agent/TCP/Reno]
$tcp set class_ 1
$ns attach-agent $n0 $tcp
set sink [new Agent/TCPSink]
$ns attach-agent $n3 $sink
$ns connect $tcp $sink
$tcp set fid_ 1

set ftp [new Application/FTP]
$ftp attach-agent $tcp

$ns at 0.5 "$ftp start"
$ns at 4.5 "$ftp stop"
$ns at 5.0 "finish"

$ns run
