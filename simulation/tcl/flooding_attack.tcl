# ==============================================================================
# JIIT Computer Networks Lab (24B15CS313)
# Scenario 2: High-Rate Flooding / Denial-of-Service Simulation
# Architecture: Adversary (n0), Victim Server (n3) via Bottleneck Gateway (n1, n2)
# ==============================================================================

set ns [new Simulator]

$ns color 1 Red
$ns color 2 Blue

set tracefile [open flooding_attack.tr w]
$ns trace-all $tracefile

set namfile [open flooding_attack.nam w]
$ns namtrace-all $namfile

proc finish {} {
    global ns tracefile namfile
    $ns flush-trace
    close $tracefile
    close $namfile
    puts "Flooding Attack Simulation Completed. Output saved to flooding_attack.tr"
    exit 0
}

set n0 [$ns node]
set n1 [$ns node]
set n2 [$ns node]
set n3 [$ns node]

$n0 label "Attacker (n0)"
$n1 label "Ingress Router (n1)"
$n2 label "Bottleneck Link (n2)"
$n3 label "Target Server (n3)"

# Constrained bottleneck link between n1 and n2
$ns duplex-link $n0 $n1 10Mb 5ms DropTail
$ns duplex-link $n1 $n2 2Mb 20ms DropTail
$ns duplex-link $n2 $n3 10Mb 5ms DropTail

# Strict queue limit causing heavy packet loss under flood
$ns queue-limit $n1 $n2 10

# High-Rate UDP Flood Generator (5 Mbps into a 2 Mbps link)
set udp0 [new Agent/UDP]
$ns attach-agent $n0 $udp0
set null0 [new Agent/Null]
$ns attach-agent $n3 $null0
$ns connect $udp0 $null0
$udp0 set fid_ 1

set cbr0 [new Application/Traffic/CBR]
$cbr0 attach-agent $udp0
$cbr0 set packet_size_ 1024
$cbr0 set rate_ 8Mb
$cbr0 set interval_ 0.001

# Legitimate TCP Connection attempting to communicate simultaneously
set tcp [new Agent/TCP]
$tcp set class_ 2
$ns attach-agent $n1 $tcp
set sink [new Agent/TCPSink]
$ns attach-agent $n3 $sink
$ns connect $tcp $sink
$tcp set fid_ 2

set ftp [new Application/FTP]
$ftp attach-agent $tcp

$ns at 0.2 "$ftp start"
$ns at 0.5 "$cbr0 start"
$ns at 4.5 "$cbr0 stop"
$ns at 4.8 "$ftp stop"
$ns at 5.0 "finish"

$ns run
