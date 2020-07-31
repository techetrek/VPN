# VPN

Script per installazione VPN RoadWarrior

Lo script funziona su Ubuntu ed è stato testato sulle versioni 18.04 o superiori

Una volta collegati in SSH come root al vostro server lanciare questi comandi:

wget https://raw.githubusercontent.com/techetrek/VPN/master/vpn-install.sh

chmod +x vpn-install.sh

/bin/bash vpn-install.sh

Lo script permette di scegliere alcuni parametri, fornendo anche delle scelte standard, l'unica opzione da specificare è il nome del client.
Installa openvpn e genera i certificati e i file di configurazione server e client.

Alla fine chiede se modificare le regole iptables, per farlo installa iptables-persistent, salva le attuali regole iptables, e aggiunge questa regola:

iptables -t nat -A POSTROUTING -s $vpn_private_subnet ! -d $vpn_private_subnet -j SNAT --to-source $ip

oltre ad abilitare anche il forward dei pacchetti, rimuovendo il commento da #net.ipv4.ip_forward=1 in sysctl.conf

Terminato tutto il processo si può recuperare il file di configurazione per il client dalla cartella /etc/openvpn/client , tramite Filezilla o progamma simile
