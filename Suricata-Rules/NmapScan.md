# NMAP Tarama Algılama Kuralları

## SYN Taraması -sS (T1-T5 hızları arasında)

### Kural 1:
```shell
alert tcp any any -> any [21,22,23,25,53,80,88,110,135,137,138,139,143,161,389,443,445,465,514,587,636,853,993,995,1194,1433,1720,3306,3389,8080,8443,11211,27017,51820] (msg:"POSSBL PORT SCAN (NMAP -sS)"; flow:to_server,stateless; flags:S; window:1024; tcp.mss:1460; threshold:type threshold, track by_src, count 20, seconds 70; classtype:attempted-recon; sid:3400001; priority:2; rev:1;)
```
- **Açıklama**: NMAP SYN taraması (T1-T5 hızları arasında) tespit eder.
- **Detaylar**: 
  - Hedeflenen yaygın portlar listelenmiştir.
  - SYN bayrağı (flags:S) ile gönderilen trafiği izler.
  - Kaynaktan gelen ve 70 saniye içinde 20 defa eşleşen trafiği algılar.

### Kural 2:
```shell
alert tcp any any -> any ![21,22,23,25,53,80,88,110,135,137,138,139,143,161,389,443,445,465,514,587,636,853,993,995,1194,1433,1720,3306,3389,8080,8443,11211,27017,51820] (msg:"POSSBL PORT SCAN (NMAP -sS)"; flow:to_server,stateless; flags:S; window:1024; tcp.mss:1460; threshold:type threshold, track by_src, count 7, seconds 135; classtype:attempted-recon; sid:3400002; priority:2; rev:2;)
```
- **Açıklama**: NMAP SYN taraması (T1-T5 hızları arasında) tespit eder.
- **Detaylar**: 
  - Yaygın olmayan portlar hedeflenmiştir.
  - SYN bayrağı (flags:S) ile gönderilen trafiği izler.
  - Kaynaktan gelen ve 135 saniye içinde 7 defa eşleşen trafiği algılar.

## SYN-ACK 3-Yönlü Tarama -sT (T2-T5 hızları arasında)

### Kural:
```shell
alert tcp any ![22,25,53,80,88,143,443,445,465,587,853,993,1194,8080,51820] -> any ![22,25,53,80,88,143,443,445,465,587,853,993,1194,8080,51820] (msg:"POSSBL PORT SCAN (NMAP -sT)"; flow:to_server; window:32120; flags:S; threshold:type threshold, track by_src, count 20, seconds 70; classtype:attempted-recon; sid:3400003; rev:3;)
```
- **Açıklama**: NMAP SYN-ACK 3-yönlü taraması (T2-T5 hızları arasında) tespit eder.
- **Detaylar**: 
  - Yaygın olmayan portlar arasında gerçekleşen SYN bayrağı ile trafiği izler.
  - Kaynaktan gelen ve 70 saniye içinde 20 defa eşleşen trafiği algılar.

## ACK Taraması -sA (T2-T5 hızları arasında)

### Kural:
```shell
alert tcp any ![22,25,53,80,88,143,443,445,465,587,853,993,1194,8080,51820] -> any ![22,25,53,80,88,143,443,445,465,587,853,993,1194,8080,51820] (msg:"POSSBL PORT SCAN (NMAP -sA)"; flags:A; flow:stateless; window:1024; threshold:type threshold, track by_dst, count 20, seconds 70; classtype:attempted-recon; sid:3400004; priority:2; rev:5;)
```
- **Açıklama**: NMAP ACK taraması (T2-T5 hızları arasında) tespit eder.
- **Detaylar**: 
  - Yaygın olmayan portlar arasında gerçekleşen ACK bayrağı ile trafiği izler.
  - Hedefe yönelik olup, 70 saniye içinde 20 defa eşleşen trafiği algılar.

## Christmas Tree Taraması -sX (T1-T5 hızları arasında)

### Kural:
```shell
alert tcp any any -> any any (msg:"POSSBL PORT SCAN (NMAP -sX)"; flags:FPU; flow:to_server,stateless; threshold:type threshold, track by_src, count 3, seconds 120; classtype:attempted-recon; sid:3400005; rev:2;)
```
- **Açıklama**: NMAP Christmas Tree taraması (T1-T5 hızları arasında) tespit eder.
- **Detaylar**: 
  - FIN, PSH ve URG bayrakları (flags:FPU) ile gönderilen trafiği izler.
  - Kaynaktan gelen ve 120 saniye içinde 3 defa eşleşen trafiği algılar.

## Parçalı Tarama -f (T1-T5 hızları arasında)

### Kural:
```shell
alert ip any any -> any any (msg:"POSSBL SCAN FRAG (NMAP -f)"; fragbits:M+D; threshold:type limit, track by_src, count 3, seconds 1210; classtype:attempted-recon; sid:3400006; priority:2; rev:6;)
```
- **Açıklama**: NMAP parçalı tarama (T1-T5 hızları arasında) tespit eder.
- **Detaylar**: 
  - Daha fazla ve ilk parça bayrakları (fragbits:M+D) ile gönderilen trafiği izler.
  - Kaynaktan gelen ve 1210 saniye içinde 3 defa eşleşen trafiği algılar.

## UDP Taraması -sU (T1-T5 hızları arasında)

### Kural 1:
```shell
alert udp any any -> any [53,67,68,69,123,161,162,389,520,1026,1027,1028,1029,1194,1434,1900,11211,12345,27017,51820] (msg:"POSSBL PORT SCAN (NMAP -sU)"; flow:to_server,stateless; classtype:attempted-recon; sid:3400007; priority:2; rev:6; threshold:type threshold, track by_src, count 20, seconds 70; dsize:0;)
```
- **Açıklama**: NMAP UDP taraması (T1-T5 hızları arasında) tespit eder.
- **Detaylar**: 
  - Yaygın UDP portları hedeflenmiştir.
  - Veri boyutu sıfır olan UDP paketlerini izler.
  - Kaynaktan gelen ve 70 saniye içinde 20 defa eşleşen trafiği algılar.

### Kural 2:
```shell
alert udp any any -> any ![53,67,68,69,123,161,162,389,520,1026,1027,1028,1029,1194,1434,1900,11211,12345,27017,51820] (msg:"POSSBL PORT SCAN (NMAP -sU)"; flow:to_server,stateless; classtype:attempted-recon; sid:3400008; priority:2; rev:6; threshold:type threshold, track by_src, count 7, seconds 135; dsize:0;)
```
- **Açıklama**: NMAP UDP taraması (T1-T5 hızları arasında) tespit eder.
- **Detaylar**: 
  - Yaygın olmayan UDP portları hedeflenmiştir.
  - Veri boyutu sıfır olan UDP paketlerini izler.
  - Kaynaktan gelen ve 135 saniye içinde 7 defa eşleşen trafiği algılar.

## Hedef Port 4444 Taramaları

### TCP Hedef Port: 4444
```shell
alert tcp any ![21,22,23,25,53,80,88,110,135,137,138,139,143,161,389,443,445,465,514,587,636,853,993,995,1194,1433,1720,3306,3389,8080,8443,11211,27017,51820] -> any 4444 (msg:"POSSBL SCAN SHELL M-SPLOIT TCP"; classtype:trojan

-activity; sid:3400020; priority:1; rev:2;)
```
- **Açıklama**: Metasploit gibi araçlar tarafından kullanılan TCP hedef port 4444'ü tespit eder.
- **Detaylar**: 
  - Yaygın olmayan portlardan gelen ve hedef portu 4444 olan TCP trafiğini izler.

### UDP Hedef Port: 4444
```shell
alert udp any ![53,67,68,69,123,161,162,389,520,1026,1027,1028,1029,1194,1434,1900,11211,12345,27017,51820] -> any 4444 (msg:"POSSBL SCAN SHELL M-SPLOIT UDP"; classtype:trojan-activity; sid:3400021; priority:1; rev:2;)
```
- **Açıklama**: Metasploit gibi araçlar tarafından kullanılan UDP hedef port 4444'ü tespit eder.
- **Detaylar**: 
  - Yaygın olmayan portlardan gelen ve hedef portu 4444 olan UDP trafiğini izler.

Bu kurallar ve açıklamaları, NMAP taramalarını ve belirli hedef port trafiğini tespit etmek için kapsamlı bir rehber sunar.
