#!/bin/bash
#
# https://github.com/siz1103/VPN/blob/master/vpn-install.sh
#

#Funzioni Principali
check_iniziali(){
	#Verifica che lo script sia eseguito come root
	if [[ "$EUID" -ne 0 ]]; then
		echo "  - ATTENZIONE!!! Lo script va eseguito con privilegi di root..."
		echo "  - Uscita in corso... "
		exit
	fi

	#Verifica che il server abbia il sistema operativo corretto
	if grep -qs "ubuntu" /etc/os-release; then
		os="ubuntu"
		versione_os=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	  nome_server=$(cat /etc/hostname )
	else
	  echo "  - ATTENZIONE!!! Per ora lo script è compatibile solo con Ubuntu..."
		echo "  - Uscita in corso... "
	  exit
	fi
	if [[ "$os" == "ubuntu" && "$versione_os" -lt 1804 ]]; then
			echo "  - ATTENZIONE!!! Per eseguire lo script serve almeno la versione 18.04 di Ubuntu ..."
			echo "  - Uscita in corso... "
		exit
	fi

	vpn_private_subnet=192.168.253.0/24

}

#Generazione configurazione server
nuovo_server(){
echo
echo "  - Creazione del file di configurazione in corso ..."
echo
sleep 2
echo "local $ip
port $porta
proto $protocollo
dev tun
ca /etc/openvpn/easy-rsa/keys/ca.crt
cert /etc/openvpn/easy-rsa/keys/$nome_server.crt
key /etc/openvpn/easy-rsa/keys/$nome_server.key
dh /etc/openvpn/easy-rsa/keys/dh.pem
auth SHA512
tls-crypt /etc/openvpn/easy-rsa/keys/ta.key
topology subnet
server $network $netmask
push 'redirect-gateway def1 bypass-dhcp'
ifconfig-pool-persist ipp.txt
push 'dhcp-option DNS 8.8.8.8'
push 'dhcp-option DNS 8.8.4.4'
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3" > /etc/openvpn/$nome_server.conf
if [[ "$protocollo" = "udp" ]]; then
	echo "explicit-exit-notify" >> /etc/openvpn/$nome_server.conf
fi
}

nuovo_client(){
echo
echo "  - Creazione del client in corso ..."
echo
sleep 2
parametri=/etc/openvpn/client/$nome_server.param
ip=$(cat $parametri |grep ip|awk '{print $2}')
porta=$(cat $parametri |grep porta|awk '{print $2}')
protocollo=$(cat $parametri |grep protocollo|awk '{print $2}')
echo "client
dev tun
proto $protocollo
remote $ip $porta
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3
<ca>" > /etc/openvpn/client/$1.ovpn
cat /etc/openvpn/easy-rsa/keys/ca.crt >> /etc/openvpn/client/$1.ovpn
echo "</ca>
<cert>" >> /etc/openvpn/client/$1.ovpn
sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/easy-rsa/keys/$1.crt >> /etc/openvpn/client/$1.ovpn
echo "</cert>
<key>" >> /etc/openvpn/client/$1.ovpn
cat /etc/openvpn/easy-rsa/keys/$1.key >> /etc/openvpn/client/$1.ovpn
echo "</key>
<tls-crypt>" >> /etc/openvpn/client/$1.ovpn
sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/easy-rsa/keys/ta.key >> /etc/openvpn/client/$1.ovpn
echo "</tls-crypt>" >> /etc/openvpn/client/$1.ovpn
}

#Generazione Certificati
genera_certificati(){
	cd /etc/openvpn/easy-rsa/
	. ./vars &>/dev/null
	case "$1" in
		server)
			./clean-all &>/dev/null
			echo
			echo "  - Creazione diffie-hellman in corso ... Potrebbe richiedere tempo ..."
			echo
			export KEY_SIZE=2048
			./build-dh &>/dev/null
			mv keys/dh2048.pem keys/dh.pem
			echo
			echo "  - Creazione certificato CA in corso ..."
			echo
			./pkitool --initca &>/dev/null
			echo
			echo "  - Creazione certificati server in corso ..."
			echo
			openvpn --genkey --secret keys/ta.key &>/dev/null
			./pkitool --server $nome_server &>/dev/null
		;;
		client)
		if [[ ! -e /etc/openvpn/easy-rsa/keys/$client.crt && ! -e /etc/openvpn/easy-rsa/keys/$client.key ]]; then
			echo
			echo "  - Creazione certificati client in corso ..."
			echo
			./pkitool $client &>/dev/null
		fi
		;;
	esac
}

#Scelta Parametri
scelta_parametri(){
	case "$1" in
		server)
			if [[ ! -e /etc/openvpn/server/$nome_server.conf ]]; then
				echo
	  		echo "  - Creazione della configurazione in corso, puoi scegliere i parametri o mantenere quelli preimpostati"
	  		echo
	  		if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
	  			ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	  		else
	  			multi_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
	  			echo
	  			echo "  - Sul server è stato rilevato più di un IP, quale vuoi usare?"
					echo
	  			ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
	  			read -p "  - Indirizzo IPv4 [1]: " ip_scelto
	  			until [[ -z "$multi_ip" || "$multi_ip" =~ ^[0-9]+$ && "$ip_scelto" -le "$multi_ip" ]]; do
	  				echo "	- $multi_ip: scelta errata. Inserirla nuovamente"
	  				read -p "  - Indirizzo IPv4 [1]: " ip_scelto
	  			done
	  			[[ -z "$multi_ip" ]] && $multi_ip="1"
	  			ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_scelto"p)
	  		fi
	  		if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
	  			echo
	  			echo "  - Non è stato rilevato un ip pubblico, indicare l'indirizzo IP con cui il server viene raggiunto"
					echo
	  			#ip_rilevato=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
					ip_rilevato=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ifconfig.me/" || curl -m 10 -4Ls "http://ifconfig.me/")")
	  			read -p "  - IP Pubblico [$ip_rilevato]: " ip_pubblico
	  			until [[ -n "$ip_rilevato" || -n "$ip_pubblico" ]]; do
	  				echo "  - L'IP inserito non è corretto."
	  				read -p "  - IP Pubblico: " ip_pubblico
	  			done
	  			[[ -z "$ip_pubblico" ]] && $ip_pubblico="$ip_rilevato"
	  		fi
	  		echo
	  		echo "  - Che protocollo vuoi usare?"
	  		echo "    1) UDP (raccomandato)"
	  		echo "    2) TCP"
	  		read -p "  - Protocollo [1]: " protocollo
	  		until [[ -z "$protocollo" || "$protocollo" =~ ^[12]$ ]]; do
					echo
	  			echo "  - $protocollo: scelta non valida."
	  			read -p "  - Protocollo [1]: " protocollo
	  		done
	  		case "$protocollo" in
	  			1|"")
	  			protocollo=udp
	  			;;
	  			2)
	  			protocollo=tcp
	  			;;
	  		esac
	  		echo
	  		echo "  - Su che porta vuoi attivare la VPN?"
	  		read -p "  - Porta [1194]: " porta
				if [ -z "$porta" ]; then
					if [ "$(netstat -tulpn | grep 1194 )" ]; then
							porta_utilizzata=1
	    			else
	      			porta_utilizzata=0
	    			fi
				else
	  			if [ "$(netstat -tulpn | grep $porta )" ]; then
	    			porta_utilizzata=1
	  			else
	    			porta_utilizzata=0
	  			fi
				fi
	  		until [[ "$porta_utilizzata" = "0" && ( -z "$porta" || "$porta" =~ ^[0-9]+$ && "$porta" -le 65535 ) ]]; do
					echo
	  			echo "  - $porta: porta non valida."
					echo
	  			read -p "  - Porta [1194]: " porta
					if [ -z "$porta" ]; then
						if [ "$(netstat -tulpn | grep 1194 )" ]; then
							porta_utilizzata=1
	    			else
	      			porta_utilizzata=0
	    			fi
					else
	    			if [ "$(netstat -tulpn | grep $porta )" ]; then
	      			porta_utilizzata=1
	    			else
	      			porta_utilizzata=0
	    			fi
					fi
	  		done
	  		[[ -z "$porta" ]] && porta="1194"
				echo "ip $ip" > /etc/openvpn/client/$nome_server.param
				echo "porta $porta" >> /etc/openvpn/client/$nome_server.param
				echo "protocollo $protocollo" >> /etc/openvpn/client/$nome_server.param
			fi
		;;
		client)
			echo
			read -p "  - Scegli un nome da assegnare al client: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			until [[ ! -f /etc/openvpn/client/$client.ovpn && ! -e /etc/openvpn/easy-rsa/keys/$client.crt && ! -z $unsanitized_client ]]; do
				echo
				read -p "  - Il nome del client non è utilizzabile, specificarne un altro: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			[[ -z "$client" ]]
		;;
	esac
}


check_iniziali

#Installazione dei pacchetti necessari
echo
echo "  - Installazione pacchetti in corso ... Attendere ..."
echo

apt-get update  &>/dev/null
apt-get install -y openvpn easy-rsa ipcalc &>/dev/null

network=$(ipcalc $vpn_private_subnet|grep Address |awk '{print $2}')
netmask=$(ipcalc $vpn_private_subnet|grep Netmask |awk '{print $2}')

#Creazione delle directory necessarie e importazione file EasyRSA
echo
echo "  - Creazione delle cartelle necessarie in corso ..."
sleep 2
mkdir -p /etc/openvpn/ccd
mkdir -p /etc/openvpn/easy-rsa
mkdir -p /etc/openvpn/server
mkdir -p /etc/openvpn/client
cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa
ln -sfn /usr/share/easy-rsa/openssl-1.0.0.cnf /etc/openvpn/easy-rsa/openssl.cnf

#Generazione certificati server
if [[ ! -e /etc/openvpn/easy-rsa/keys/ca.crt && ! -e /etc/openvpn/easy-rsa/keys/$nome_server.crt && ! -e /etc/openvpn/easy-rsa/keys/$nome_server.key && ! -e /etc/openvpn/easy-rsa/keys/dh.pem ]]; then
	echo
	echo "  - Creazione dei certificati in corso ..."
	sleep 2
	genera_certificati "server"
fi


#Scelta Parametri
scelta_parametri "server"

#Generazione configurazione server
nuovo_server

#Generazione certificati client
while [[ -z $risposta || "$risposta" = "Y" || "$risposta" = "y" ]]; do
	read -p "  - Aggiungere un nuovo client? [y/n]: " risposta
	case "$risposta" in
		y|Y)
		scelta_parametri "client"
		genera_certificati "client"
		nuovo_client "$client"
		;;
		n|N)
		break
		;;
		*)
		echo
		echo "  - ATTENZIONE!!! Scelta non valida..."
		echo
		;;
	esac
done

systemctl enable openvpn@$nome_server &>/dev/null
systemctl start openvpn@$nome_server &>/dev/null

unset risposta
while [[ -z $risposta ]]; do
	echo
	read -p "  - Vuoi che vengano aggiunte automaticamente le regole al firewall? [y/n]: " risposta
	case "$risposta" in
		y|Y)
		export DEBIAN_FRONTEND=noninteractive
		echo "iptables-persistent iptables-persistent/autosave_v6 select true" |debconf-set-selections
		echo "iptables-persistent iptables-persistent/autosave_v4 select true" |debconf-set-selections
		apt-get install -y iptables-persistent &>/dev/null
		sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
		sysctl -p &>/dev/null
		iptables -t nat -A POSTROUTING -s $vpn_private_subnet ! -d $vpn_private_subnet -j SNAT --to-source $ip
		iptables-save &>/dev/null
		;;
		n|N)
		echo "  - Ricordati di abilitare il forward e aggiungere questa regola al firewall: "
		echo "    iptables -t nat -A POSTROUTING -s $vpn_private_subnet ! -d $vpn_private_subnet -j SNAT --to-source $ip"
		;;
		*)
		echo
		echo "  - ATTENZIONE!!! Scelta non valida... "
		echo
		unset risposta
		;;
	esac
done

echo
echo " _._._._._._._._._._._._._._._._._._._.__._._._._._._._._._._._._._._._._._._._._._._._."
echo "|                                                                                       |"
echo "|   La creazione della VPN RoadWarrior o dei client è terminata                         |"
echo "|   I file da importare sui client si trovano nella cartella /etc/openvpn/client        |"
echo "|   Puoi scaricarli con un client SFTP tipo Filezilla, o il tuo preferito               |"
echo "|                                                                                       |"
echo "|   Per ogni segnalazione,richiesta, o consiglio, puoi scrivere a techetrek@gmail.com   |"
echo "|   Grazie per aver utilizzato questo script                                            |"
echo "|_._._._._._._._._._._._._._._._._._._.__._._._._._._._._._._._._._._._._._._._._._._._.|"
echo
