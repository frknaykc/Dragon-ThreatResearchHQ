Aşağıda FireEye ihlaliyle ilgili kurallar ve açıklamaları bulunmaktadır. Bu kurallar, FireEye'nin sızma test araçlarının yetkisiz erişimi sonrasında oluşturulmuştur ve belirli kötü amaçlı etkinlikleri ve geri kapı (backdoor) trafiğini tespit etmek için kullanılmaktadır.

# FireEye İhlali Algılama Kuralları

## 1. Backdoor.HTTP.BEACON.[CSBundle USAToday Server]

```shell
alert tcp any $HTTP_PORTS -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle USAToday Server]"; flow:from_server,established; content:"{\"navgd\":\"<div class=gnt_n_dd_ls_w><div class=gnt_n_dd_nt>ONLY AT USA TODAY:</div><div class=gnt_n_dd_ls><a class=gnt_n_dd_ls_a href=https://supportlocal.usatoday.com/"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000300; rev:1;)
```
- **Açıklama**: USA Today sunucusundan gelen belirli bir JSON yapısını tespit eder.
- **Detaylar**: HTTP yanıtında belirli içerik bulunur ve bu içerik USA Today'e özgü bir URL'yi içerir.

## 2. Backdoor.HTTP.BEACON.[CSBundle USAToday Server]

```shell
alert tcp any $HTTP_PORTS -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle USAToday Server]"; content:"HTTP/1."; depth:7; content:"Connection: close"; content:"Content-Type: application/json\; charset=utf-8"; content:"Content-Security-Policy: upgrade-insecure-requests"; content:"Strict-Transport-Security: max-age=10890000"; content:"Cache-Control: public, immutable, max-age=315360000"; content:"Accept-Ranges: bytes"; content:"X-Cache: HIT, HIT"; content:"X-Timer: S1593010188.776402,VS0,VE1"; content:"Vary: X-AbVariant, X-AltUrl, Accept-Encoding"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000301; rev:1;)
```
- **Açıklama**: USA Today sunucusundan gelen HTTP yanıtlarında belirli başlıkları tespit eder.
- **Detaylar**: HTTP yanıtında bir dizi belirli başlık ve içerik bulunur.

## 3. Backdoor.HTTP.BEACON.[CSBundle Original Server]

```shell
alert tcp any $HTTP_PORTS -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle Original Server]"; content:"HTTP/1."; depth:7; content:"Content-Type: text/json|0d 0a|"; content:"Server: Microsoft-IIS/10.0|0d 0a|"; content:"X-Powered-By: ASP.NET|0d 0a|"; content:"Cache-Control: no-cache, no-store, max-age=0, must-revalidate|0d 0a|"; content:"Pragma: no-cache|0d 0a|"; content:"X-Frame-Options: SAMEORIGIN|0d 0a|"; content:"Connection: close|0d 0a|"; content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000302; rev:1;)
```
- **Açıklama**: Microsoft IIS sunucusundan gelen belirli JSON yapısını ve HTTP başlıklarını tespit eder.
- **Detaylar**: HTTP yanıtında bir dizi belirli başlık ve JSON içerik bulunur.

## 4. Backdoor.HTTP.BEACON.[CSBundle NYTIMES GET]

```shell
alert tcp any any -> any $HTTP_PORTS (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle NYTIMES GET]"; content:"GET"; depth:3; content:"Accept: */*"; content:"Accept-Encoding: gzip, deflate, br"; content:"Accept-Language: en-US,en\;q=0.5"; content:"nyt-a="; content:"nyt-gdpr=0\;nyt-purr=cfh\;nyt-geo=US}"; fast_pattern; content:"|0d 0a|Cookie:"; pcre:"/^GET\s(?:\/ads\/google|\/vi-assets\/static-assets|\/v1\/preferences|\/idcta\/translations|\/v2\/preferences)/"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000303; rev:1;)
```
- **Açıklama**: NY Times sunucusuna yapılan belirli GET isteklerini tespit eder.
- **Detaylar**: HTTP GET isteğinde bir dizi belirli başlık ve çerez içerir.

## 5. Backdoor.HTTP.BEACON.[CSBundle Original Stager]

```shell
alert tcp any any -> any $HTTP_PORTS (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle Original Stager]"; content:"T "; offset:2; depth:3; content:"Accept: */*"; content:"Accept-Language: en-US"; content:"Accept-Encoding: gzip, deflate"; content:"Cookie: SIDCC=AN0-TYutOSq-fxZK6e4kagm70VyKACiG1susXcYRuxK08Y-rHysliq0LWklTqjtulAhQOPH8uA"; pcre:"/\/api\/v1\/user\/(?:512|124)\/avatar/"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000304; rev:1;)
```
- **Açıklama**: Belirli bir URI içeren ve belirli çerezlere sahip GET isteklerini tespit eder.
- **Detaylar**: HTTP GET isteğinde belirli çerezler ve URI içerir.

## 6. Backdoor.HTTP.GORAT.[SID1]

```shell
alert tcp any any -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.GORAT.[SID1]"; content:"GET"; depth:3; content:"|0d 0a|Cookie: SID1="; content:!"|0d 0a|Referer:"; content:!"|0d 0a|Accept"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000305; rev:1;)
```
- **Açıklama**: Belirli bir çerez ve belirli başlıkları içermeyen GET isteklerini tespit eder.
- **Detaylar**: HTTP GET isteğinde "SID1" çerezini içerir ve belirli başlıklar bulunmaz.

## 7. Backdoor.HTTP.BEACON.[CSBundle MSOffice Server]

```shell
alert tcp any $HTTP_PORTS -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle MSOffice Server]"; content:"HTTP/1."; depth:7; content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":\""; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000306; rev:1;)
```
- **Açıklama**: Microsoft Office sunucusundan gelen belirli JSON yapısını tespit eder.
- **Detaylar**: HTTP yanıtında belirli JSON içerik bulunur.

## 8. Backdoor.SSL.BEACON.[CSBundle Ajax]

```shell
alert tcp any any -> any 443 (msg:"[FIREEYE-IOC] Backdoor.SSL.BEACON.[CSBundle Ajax]"; content:"|16 03|"; depth:2; content:"US"; content:"US"; distance:0; content:"ajax.microsoft.com"; content:"ajax.microsoft.com"; distance:0; content:"Seattle"; content:"Seattle"; distance:0; content:"Microsoft"; content:"Microsoft"; distance:0; content:"Information Technologies"; content:"Information Technologies"; distance:0; content:"WA"; content:"WA"; distance:0; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:target

ed-activity; sid:10000307; rev:1;)
```
- **Açıklama**: Belirli SSL bağlantılarını ve Microsoft Ajax sunucusunu tespit eder.
- **Detaylar**: SSL handshake sırasında belirli içerik ve başlıklar bulunur.

## 9. Backdoor.HTTP.BEACON.[Yelp GET]

```shell
alert tcp $HOME_NET any -> any $HTTP_PORTS (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[Yelp GET]"; flow:to_server; content:"GET "; depth:4; content:"&parent_request_id="; distance:0; within:256; fast_pattern; content:" HTTP/1"; distance:0; within:1024; content:"|0d 0a|Sec-Fetch-Dest: empty|0d 0a|"; distance:0; within:256; content:"request_origin=user"; offset:0; depth:256; pcre:"/^GET [^\r\n]{0,256}&parent_request_id=(?:[A-Za-z0-9_\/\+\-%]{128,1024})={0,2}[^\r\n]{0,256} HTTP\/1\.[01]/"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000308; rev:1;)
```
- **Açıklama**: Yelp sunucusuna yapılan belirli GET isteklerini tespit eder.
- **Detaylar**: HTTP GET isteğinde belirli başlıklar ve URI parametreleri bulunur.

## 10. Backdoor.DNS.BEACON.[CSBundle DNS]

```shell
alert udp any 53 -> any any (msg:"[FIREEYE-IOC] Backdoor.DNS.BEACON.[CSBundle DNS]"; content:"|00 01 00 01|"; offset:4; depth:4; content:"|0a|_domainkey"; distance:0; content:"|00 00 10 00 01 c0 0c 00 10 00 01 00 00 00 02 01 00 ff|v=DKIM1\; p="; distance:0; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000309; rev:1;)
```
- **Açıklama**: Belirli DNS isteklerini ve DKIM anahtarını içeren içerikleri tespit eder.
- **Detaylar**: DNS isteğinde belirli içerikler ve DKIM yapılandırması bulunur.

## 11. Backdoor.HTTP.BEACON.[CSBundle CDN GET]

```shell
alert tcp any any -> any $HTTP_PORTS (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle CDN GET]"; content:"GET"; depth:3; content:"Accept: */*"; content:"Accept-Encoding: gzip, deflate, br"; content:"Accept-Language: en-US|0d 0a|"; content:"client-="; content:"\;auth=1}"; content:"Cookie:"; pcre:"/^GET\s(?:\/v1\/queue|\/v1\/profile|\/v1\/docs\/wsdl|\/v1\/pull)/"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000310; rev:1;)
```
- **Açıklama**: CDN üzerinden belirli GET isteklerini tespit eder.
- **Detaylar**: HTTP GET isteğinde belirli başlıklar ve URI içerikleri bulunur.

## 12. Backdoor.HTTP.BEACON.[CSBundle USAToday GET]

```shell
alert tcp any any -> any $HTTP_PORTS (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle USAToday GET]"; content:"GET"; depth:3; content:"Connection: close|0d 0a|"; content:"Accept: */*|0d 0a|"; content:"gnt_ub=86\;gnt_sb=18\;usprivacy=1YNY\;DigiTrust.v1.identity="; content:"%3D\;GED_PLAYLIST_ACTIVITY=W3sidSI6IkZtTWUiLCJ0c2wiOjE1OTMwM\;"; content:"Cookie:"; pcre:"/^GET\s(?:\/USAT-GUP\/user\/|\/entertainment\/|\/entertainment\/navdd-q1a2z3Z6TET4gv2PNfXpaJAniOzOajK7M\.min\.json|\/global-q1a2z3C4M2nNlQYzWhCC0oMSEFjQbW1KA\.min\.json|\/life\/|\/news\/weather\/|\/opinion\/|\/sports\/|\/sports\/navdd-q1a2z3JHa8KzCRLOQAnDoVywVWF7UwxJs\.min\.json|\/tangstatic\/js\/main-q1a2z3b37df2b1\.min\.js|\/tangstatic\/js\/pbjsandwich-q1a2z300ab4198\.min\.js|\/tangstatic\/js\/pg-q1a2z3bbc110a4\.min\.js|\/tangsvc\/pg\/3221104001\/|\/tangsvc\/pg\/5059005002\/|\/tangsvc\/pg\/5066496002\/|\/tech\/|\/travel\/)/"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000311; rev:1;)
```
- **Açıklama**: USA Today sunucusuna yapılan belirli GET isteklerini tespit eder.
- **Detaylar**: HTTP GET isteğinde belirli çerezler ve URI içerikleri bulunur.

## 13. Backdoor.HTTP.BEACON.[CSBundle Original POST]

```shell
alert tcp any any -> any $HTTP_PORTS (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle Original POST]"; content:"POST"; depth:4; content:"Accept: */*|0d 0a|"; content:"Accept-Language: en-US|0d 0a|"; content:"Accept-Encoding: gzip, deflate|0d 0a|"; content:"{\"locale\":\"en\",\"channel\":\"prod\",\"addon\":\""; pcre:"/^POST\s(?:\/v4\/links\/check-activity\/check|\/v1\/stats|\/gql|\/api2\/json\/check\/ticket|\/1.5\/95648064\/storage\/history|\/1.5\/95648064\/storage\/tabs|\/u\/0\/_\/og\/botguard\/get|\/ev\/prd001001|\/ev\/ext001001|\/gp\/aw\/ybh\/handlers|\/v3\/links\/ping-beat\/check)/"; content:"ses-"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000312; rev:1;)
```
- **Açıklama**: Belirli bir URI içeren ve belirli çerezlere sahip POST isteklerini tespit eder.
- **Detaylar**: HTTP POST isteğinde belirli çerezler ve URI içerikleri bulunur.

## 14. Backdoor.HTTP.BEACON.[CSBundle MSOffice POST]

```shell
alert tcp any any -> any $HTTP_PORTS (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle MSOffice POST]"; content:"POST /v1/push"; depth:13; content:"Accept: */*"; content:"Accept-Encoding: gzip, deflate, br"; content:"Accept-Language: en-US|0d 0a|"; content:"{\"locale\":\"en\",\"channel\":\"prod\",\"addon\":\""; content:"cli"; content:"l-"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000313; rev:1;)
```
- **Açıklama**: Microsoft Office sunucusuna yapılan belirli POST isteklerini tespit eder.
- **Detaylar**: HTTP POST isteğinde belirli içerik ve başlıklar bulunur.

## 15. M.HackTool.SMB.Impacket-Obfuscation.[Service Names]

```shell
alert tcp any any -> any [139,445] (msg:"[FIREEYE-IOC] M.HackTool.SMB.Impacket-Obfuscation.[Service Names]"; content:"|ff 53 4d 42|"; offset:4; depth:4; pcre:"/(?:\x57\x00\x69\x00\x6e\x00\x64\x

00\x6f\x00\x77\x00\x73\x00\x20\x00\x55\x00\x70\x00\x64\x00\x61\x00\x74\x00\x65\x00\x20\x00\x43\x00\x6f\x00\x6e\x00\x74\x00\x72\x00\x6f\x00\x6c\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65|\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x31\x00\x30\x00\x20\x00\x44\x00\x65\x00\x66\x00\x65\x00\x6e\x00\x64\x00\x65\x00\x72|\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x4c\x00\x69\x00\x63\x00\x65\x00\x6e\x00\x73\x00\x65\x00\x20\x00\x4b\x00\x65\x00\x79\x00\x20\x00\x41\x00\x63\x00\x74\x00\x69\x00\x76\x00\x61\x00\x74\x00\x69\x00\x6f\x00\x6e|\x4f\x00\x66\x00\x66\x00\x69\x00\x63\x00\x65\x00\x20\x00\x33\x00\x36\x00\x35\x00\x20\x00\x50\x00\x72\x00\x6f\x00\x78\x00\x79|\x4d\x00\x69\x00\x63\x00\x72\x00\x6f\x00\x73\x00\x6f\x00\x66\x00\x74\x00\x20\x00\x53\x00\x65\x00\x63\x00\x75\x00\x72\x00\x69\x00\x74\x00\x79\x00\x20\x00\x43\x00\x65\x00\x6e\x00\x74\x00\x65\x00\x72|\x4f\x00\x6e\x00\x65\x00\x44\x00\x72\x00\x69\x00\x76\x00\x65\x00\x20\x00\x53\x00\x79\x00\x6e\x00\x63\x00\x20\x00\x43\x00\x65\x00\x6e\x00\x74\x00\x65\x00\x72|\x42\x00\x61\x00\x63\x00\x6b\x00\x67\x00\x72\x00\x6f\x00\x75\x00\x6e\x00\x64\x00\x20\x00\x41\x00\x63\x00\x74\x00\x69\x00\x6f\x00\x6e\x00\x20\x00\x4d\x00\x61\x00\x6e\x00\x61\x00\x67\x00\x65\x00\x72|\x53\x00\x65\x00\x63\x00\x75\x00\x72\x00\x65\x00\x20\x00\x54\x00\x6f\x00\x6b\x00\x65\x00\x6e\x00\x20\x00\x4d\x00\x65\x00\x73\x00\x73\x00\x61\x00\x67\x00\x69\x00\x6e\x00\x67\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65|\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x20\x00\x55\x00\x70\x00\x64\x00\x61\x00\x74\x00\x65)/R"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000314; rev:1;)
```
- **Açıklama**: Impacket araçlarıyla kullanılan SMB hizmet isimlerini tespit eder.
- **Detaylar**: SMB trafiğinde belirli hizmet isimleri bulunur.

## 16. Backdoor.HTTP.BEACON.[CSBundle Original Stager 2]

```shell
alert tcp any $HTTP_PORTS -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle Original Stager 2]"; content:"HTTP/1."; depth:7; content:"Content-Type: text/json|0d 0a|"; content:"Server: Microsoft-IIS/10.0|0d 0a|"; content:"X-Powered-By: ASP.NET|0d 0a|"; content:"Cache-Control: no-cache, no-store, max-age=0, must-revalidate|0d 0a|"; content:"Pragma: no-cache|0d 0a|"; content:"X-Frame-Options: SAMEORIGIN|0d 0a|"; content:"Connection: close|0d 0a|"; content:"Content-Type: image/gif"; content:"|01 00 01 00 00 02 01 44 00 3b|"; content:"|ff ff ff 21 f9 04 01 00 00 00 2c 00 00 00 00|"; content:"|47 49 46 38 39 61 01 00 01 00 80 00 00 00 00|"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000315; rev:1;)
```
- **Açıklama**: Microsoft IIS sunucusundan gelen belirli JSON ve GIF içeriklerini tespit eder.
- **Detaylar**: HTTP yanıtında belirli başlıklar, JSON içerikler ve GIF içerikler bulunur.

## 17. Backdoor.HTTP.BEACON.[CSBundle NYTIMES POST]

```shell
alert tcp any any -> any $HTTP_PORTS (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle NYTIMES POST]"; content:"POST"; depth:4; content:"Accept: */*"; content:"Accept-Encoding: gzip, deflate, br"; content:"Accept-Language: en-US,en\;q=0.5"; content:"id-"; content:"{\"locale\":\"en\",\"channel\":\"prod\",\"addon\":\""; pcre:"/^POST\s(?:\/track|\/api\/v1\/survey\/embed|\/svc\/weather\/v2)/"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000316; rev:1;)
```
- **Açıklama**: NY Times sunucusuna yapılan belirli POST isteklerini tespit eder.
- **Detaylar**: HTTP POST isteğinde belirli başlıklar ve URI içerikleri bulunur.

## 18. HackTool.TCP.Rubeus.[nonce 2]

```shell
alert tcp $HOME_NET any -> any 88 (msg:"[FIREEYE-IOC] HackTool.TCP.Rubeus.[nonce 2]"; content:"|a7 06 02 04 6C 69 6C 00|"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000317; rev:1;)
```
- **Açıklama**: Rubeus araçlarıyla ilişkili belirli içerikleri tespit eder.
- **Detaylar**: TCP trafiğinde belirli içerik bulunur.

## 19. Backdoor.HTTP.BEACON.[Yelp Request]

```shell
alert tcp $HOME_NET any -> any $HTTP_PORTS (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[Yelp Request]"; flow:to_server; content:"T "; depth:5; content:" HTTP/1"; distance:0; within:256; content:"Cookie: hl=en|3b|bse="; distance:0; within:256; fast_pattern; content:"|3b|_gat_global=1|3b|recent_locations|3b|_gat_www=1|3b||0d 0a|"; pcre:"/Cookie: hl=en\x3bbse=(?:[A-Za-z0-9_\/\+\-]{128,1024})={0,2}\x3b_gat_global=1\x3brecent_locations\x3b_gat_www=1\x3b\r\n/"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000318; rev:1;)
```
- **Açıklama**: Yelp sunucusuna yapılan belirli GET isteklerini tespit eder.
- **Detaylar**: HTTP GET isteğinde belir

li başlıklar ve URI içerikleri bulunur.

## 20. Backdoor.HTTP.BEACON.[CSBundle MSOffice GET]

```shell
alert tcp any any -> any $HTTP_PORTS (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle MSOffice GET]"; content:"GET"; depth:3; content:"Accept: */*"; content:"Accept-Encoding: gzip, deflate, br"; content:"Accept-Language: en-US|0d 0a|"; content:"sess-="; content:"auth=0\;loc=US}"; content:"Cookie:"; pcre:"/^GET\s(?:\/updates|\/license\/eula|\/docs\/office|\/software-activation)/"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000319; rev:1;)
```
- **Açıklama**: Microsoft Office sunucusuna yapılan belirli GET isteklerini tespit eder.
- **Detaylar**: HTTP GET isteğinde belirli başlıklar ve URI içerikleri bulunur.

## 21. Backdoor.HTTP.BEACON.[CSBundle Original Server 2]

```shell
alert tcp any $HTTP_PORTS -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle Original Server 2]"; content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000320; rev:1;)
```
- **Açıklama**: Microsoft IIS sunucusundan gelen belirli JSON yapısını tespit eder.
- **Detaylar**: HTTP yanıtında belirli JSON içerik bulunur.

## 22. Backdoor.HTTP.BEACON.[CSBundle MSOffice POST]

```shell
alert tcp any any -> any $HTTP_PORTS (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle MSOffice POST]"; content:"POST /notification"; depth:18; content:"Accept: */*"; content:"Accept-Encoding: gzip, deflate, br"; content:"Accept-Language: en-US|0d 0a|"; content:"{\"locale\":\"en\",\"channel\":\"prod\",\"addon\":\""; content:"nid"; content:"msg-"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000321; rev:1;)
```
- **Açıklama**: Microsoft Office sunucusuna yapılan belirli POST isteklerini tespit eder.
- **Detaylar**: HTTP POST isteğinde belirli içerik ve başlıklar bulunur.

## 23. Backdoor.HTTP.BEACON.[CSBundle Original GET]

```shell
alert tcp any any -> any $HTTP_PORTS (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle Original GET]"; content:"GET"; depth:3; content:"Accept: */*|0d 0a|"; content:"Accept-Language: en-US|0d 0a|"; content:"Accept-Encoding: gzip, deflate|0d 0a|"; content:"Cookie:"; content:"display-culture=en\;check=true\;lbcs=0\;sess-id="; distance:0; content:"\;SIDCC=AN0-TY21iJHH32j2m\;FHBv3=B"; pcre:"/^GET\s(?:\/api2\/json\/access\/ticket|\/api2\/json\/cluster\/resources|\/api2\/json\/cluster\/tasks|\/en-us\/p\/onerf\/MeSilentPassport|\/en-us\/p\/book-2\/8MCPZJJCC98C|\/en-us\/store\/api\/checkproductinwishlist|\/gp\/cerberus\/gv|\/gp\/aj\/private\/reviewsGallery\/get-application-resources|\/gp\/aj\/private\/reviewsGallery\/get-image-gallery-assets|\/v1\/buckets\/default\/ext-5dkJ19tFufpMZjVJbsWCiqDcclDw\/records|\/v3\/links\/ping-centre|\/v4\/links\/activity-stream|\/wp-content\/themes\/am43-6\/dist\/records|\/wp-content\/themes\/am43-6\/dist\/records|\/wp-includes\/js\/script\/indigo-migrate)/"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000322; rev:1;)
```
- **Açıklama**: Belirli bir URI içeren GET isteklerini tespit eder.
- **Detaylar**: HTTP GET isteğinde belirli başlıklar ve URI içerikleri bulunur.

## 24. Backdoor.HTTP.BEACON.[CSBundle MSOffice Server]

```shell
alert tcp any $HTTP_PORTS -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle MSOffice Server]"; flow:from_server,established; content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":\""; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000323; rev:1;)
```
- **Açıklama**: Microsoft Office sunucusundan gelen belirli JSON yapısını tespit eder.
- **Detaylar**: HTTP yanıtında belirli JSON içerik bulunur.

## 25. Backdoor.HTTP.BEACON.[CSBundle NYTIMES Server]

```shell
alert tcp any $HTTP_PORTS -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle NYTIMES Server]"; flow:from_server,established; content:"{\"meta\":{},\"status\":\"OK\",\"saved\":\"1\",\"starttime\":17656184060,\"id\":\"\",\"vims\":{\"dtc\":\""; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000324; rev:1;)
```
- **Açıklama**: NY Times sunucusundan gelen belirli JSON yapısını tespit eder.
- **Detaylar**: HTTP yanıtında belirli JSON içerik bulunur.

## 26. HackTool.UDP.Rubeus.[nonce 2]

```shell
alert udp any any -> any 88 (msg:"[FIREEYE-IOC] HackTool.UDP.Rubeus.[nonce 2]"; content:"|a7 06 02 04 6C 69 6C 00|"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000325; rev:1;)
```
- **Açıklama**: Rubeus araçlarıyla ilişkili belirli içerikleri tespit eder.
- **Detaylar**: UDP trafiğinde belirli içerik bulunur.

## 27. Backdoor.DNS.BEACON.[CSBundle DNS]

```shell
alert udp any 53 -> any any (msg:"[FIREEYE-IOC] Backdoor.DNS.BEACON.[CSBundle DNS]"; content:"|00 01 00 01|"; offset:4; depth:4; content:"|03|"; within:15; content:"|0a|_domainkey"; distance:3; within:11; content:"|00 00 10 00 01 c0 0c 00 10 00 01 00 00 00 02 01 00 ff|v=DKIM1\; p="; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000326; rev:1;)
```
- **Açıklama**: Belirli DNS isteklerini ve DKIM anahtarını içeren içerikleri tespit eder.
- **Detaylar**: DNS isteğinde belirli içerikler ve DKIM yapılandırması bulunur.

## 28. HackTool.TCP.Rubeus.[nonce]

```shell
alert tcp any any -> any 88 (msg:"[FIREEYE-IOC] HackTool.TCP.Rubeus.[nonce]"; content:"|05|"; depth:30; content:"|0a|"; distance:4; within:1; content:"Z"; content:"|6C 69 6C 00|"; within:25; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html;

 classtype:targeted-activity; sid:10000327; rev:1;)
```
- **Açıklama**: Rubeus araçlarıyla ilişkili belirli içerikleri tespit eder.
- **Detaylar**: TCP trafiğinde belirli içerik bulunur.

## 29. Backdoor.HTTP.BEACON.[CSBundle NYTIMES Server]

```shell
alert tcp any $HTTP_PORTS -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle NYTIMES Server]"; content:"HTTP/1."; depth:7; content:"Accept-Ranges: bytes"; content:"Age: 5806"; content:"Cache-Control: public,max-age=31536000"; content:"Content-Encoding: gzip"; content:"Content-Length: 256398"; content:"Content-Type: application/javascript"; content:"Server: UploadServer"; content:"Vary: Accept-Encoding, Fastly-SSL"; content:"x-api-version: F-X"; content:"x-cache: HIT"; content:"x-Firefox-Spdy: h2"; content:"x-nyt-route: vi-assets"; content:"x-served-by: cache-mdw17344-MDW"; content:"x-timer: S1580937960.346550,VS0,VE0"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000328; rev:1;)
```
- **Açıklama**: NY Times sunucusundan gelen belirli başlıkları ve içerikleri tespit eder.
- **Detaylar**: HTTP yanıtında belirli başlıklar ve içerikler bulunur.

## 30. Backdoor.HTTP.BEACON.[CSBundle Original Server 3]

```shell
alert tcp any $HTTP_PORTS -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.BEACON.[CSBundle Original Server 3]"; content:"{\"alias\":\"apx\",\"prefix\":\"\",\"suffix\":null,\"suggestions\":[],\"responseId\":\"15QE9JX9CKE2P\",\"addon\": \""; content:"\",\"shuffled\":false}"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000329; rev:1;)
```
- **Açıklama**: Microsoft IIS sunucusundan gelen belirli JSON yapısını tespit eder.
- **Detaylar**: HTTP yanıtında belirli JSON içerik bulunur.

## 31. HackTool.UDP.Rubeus.[nonce]

```shell
alert udp any any -> any 88 (msg:"[FIREEYE-IOC] HackTool.UDP.Rubeus.[nonce]"; content:"|05|"; depth:30; content:"|0a|"; distance:4; within:1; content:"Z"; content:"|6C 69 6C 00|"; within:25; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000330; rev:1;)
```
- **Açıklama**: Rubeus araçlarıyla ilişkili belirli içerikleri tespit eder.
- **Detaylar**: UDP trafiğinde belirli içerik bulunur.

## 32. Backdoor.HTTP.GORAT.[POST]

```shell
alert tcp any any -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.GORAT.[POST]"; content:"POST / HTTP/1.1"; depth:15; content:"Connection: upgrade"; content:"|0d 0a|Upgrade: tcp/1|0d 0a|"; content:!"|0d 0a|Referer:"; content:!"|0d 0a|Accept"; content:!"|0d 0a|Cookie:"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000331; rev:1;)
```
- **Açıklama**: Belirli POST isteklerini ve HTTP/1.1 bağlantı yükseltme başlıklarını tespit eder.
- **Detaylar**: HTTP POST isteğinde belirli başlıklar bulunur ve belirli başlıklar yoktur.

## 33. Backdoor.HTTP.GORAT.[Build ID]

```shell
alert tcp any any -> any any (msg:"[FIREEYE-IOC] Backdoor.HTTP.GORAT.[Build ID]"; content:"aqlKZ7wjzg0iKM00E1WB/jq9_RA46w91EKl9A02Dv/nbNdZiLsB1ci8Ph0fb64/9Ks1YxAE86iz9A0dUiDl"; reference:url,www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html; classtype:targeted-activity; sid:10000333; rev:1;)
```
- **Açıklama**: Belirli bir yapı kimliği içeren HTTP trafiğini tespit eder.
- **Detaylar**: HTTP isteğinde belirli bir yapı kimliği bulunur.

Bu kurallar, FireEye ihlali sonrasında tespit edilen kötü amaçlı etkinlikleri ve geri kapı (backdoor) trafiğini izlemek için oluşturulmuştur. 

Her bir kural, belirli başlıkları, içerikleri veya trafiği izlemek için tasarlanmıştır.

