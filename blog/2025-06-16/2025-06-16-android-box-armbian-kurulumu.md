# Android Box'a Armbian Linux İşletim Sistemi Yüklemek

Herkese selamlar. Bu rehberde Amlogic S905W işlemcili sıradan bir Android Box'ı nasıl Raspberry Pi, Orange Pi'a çevireceğiz bunu anlatacağım. Bu fikir hem bütçe ve verimlilik hem de hobi amaçlı olarak çıktı ve o şekilde ilerledi. Yazının sonunda neler yükelenebileceğini yazacağım. Neden ihtiyaç olduğu hakkında daha detaylı bir yazı gerekli. Veya deneyim kazanmak için 

## Android Box'ların İşlemcilerinin Uyumluluğu Hakkında

Piyasada sıfır veya ikinci el olarak satılan çok fazla marka, model Android Box var. Allwinner H616, H618 veya H313 serisi işlemciler, Rockchip RK3588, RK3568, RK3528, RK3328 işlemciler, Amlogic S9xxx, S905, S904, S903, S912 gibi çok fazla işlemci mevcut. Güncel Orange Pi Zero 3 cihazını örnek alırsak bu tarz yeni nesil cihazlarda H618 4 çekirdekli işlemciler kullanılıyor. Birkaç benchmark sitesini referans aldığımda performans olarak aralarında pek fark yok olarak gözüküyor. Zaten TDP değerleri doğrudan açıklanmasa da totalde en yüksek 10-15W kullanabilen cihazlar. Armbian web sitesinde topluluk olabildiğince her chipset için destek vermeye, o chipsete özel kernel build etmeye çalışıyor. 

**Eğer bu projeyi yapacaksanız önce alacağınız cihazın işlemcisinin desteğinin olup olmadığını araştırmanız gerekli. Alternatif olarak [CoreELEC](https://coreelec.org/) işletim sistemini de araştırabilirsiniz.**

## TX3 Mini Android Box ve Reset Butonu

Az önce belirttiğim şekilde ikinci el olarak araştırdığımda bu cihaza denk geldim. Hem forumlarda ismi çok geçiyordu hem de işlemcisi uyumlu gözüküyordu. İkinci el olarak satın aldım. 

TX3 Mini Donanımı: 2GB RAM, S905W 4 Çekirdek işlemci, 1x Ethernet Portu (RJ45), Güç girişi (5W 2A Adaptör), AV, HDMI Portu, SD Kart girişi, birkaç işime yaramayan giriş daha, USB portları ve yanında gelen kumanda. 

![](tx3mini.png)

**Diğer cihazların aksine AV Portu içerisine gizlenmiş bir reset tuşu veya herhangi bir reset tuşu bulunmuyor. Cihazı alırken bunu da göz ardı etmeyin. Veya uyguladığım yöntemle kullanabilirsiniz. Cihazı reset sonrası boot edeceğimiz için önemli.**

## Uygun Linux Dağıtımını ve Kerneli Bulma

Öncelikle bu noktada Google'da arayarak veya [Armbian Download](https://www.armbian.com/download/) sayfasından ilerleyebilirsiniz. Ben bu cihaz için 

"https://www.armbian.com/amlogic-s9xx-tv-box/" sayfasında bulunan "Server images with Armbian Linux v6.12" kısmındaki "Ubuntu 24.04 (Noble)" sürümünü kullandım.
(Armbian_community_25.8.0-trunk.90_Aml-s9xx-box_noble_current_6.12.31.img)

Alternatif olarak araştırabileceğiniz diğer repolar:
"https://github.com/ophub/amlogic-s9xxx-armbian"
(Birçok işlemciye destek mevcut) (Bu repo'dan da uygun ISO'yu (Armbian_25.08.0_amlogic_s905w_jammy_6.12.31_server_2025.06.01.img) denediğimde çalışmamıştı ama yöntemim yanlıştı. Tekrar denersem çalışabilir.)

- https://github.com/NickAlilovic/build
- https://github.com/LYU4662/h618-build
- https://github.com/ophub/kernel
- https://github.com/sicXnull/armbian-build/tree/X96Q-TVBOX-LPDDR3

- https://github.com/ophub/amlogic-s9xxx-armbian/blob/11dbe090ca7b53d3415ecabf48b1e276b2438c66/build-armbian/armbian-files/common-files/etc/model_database.conf#L93C4-L93C4
(Her model için database)

## SD Kart'a İmajı Yazmak

### SD Kart Boyutu & Kalitesi
Minimum 8 GB olmak şartıyla kullanacağınız kartın boyutu tamamen opsiyonel, Class 10 ve üzeri kalitede olması önemli. "Kioxia Exceria 64GB microSDXC Kart (100MB/s okuma)" kullandım ve performans olarak bir eksiklik hissetmedim. 

Bu adımda balenaEtcher adlı yazılımı kullanacağız. Rufus da kullanabilirsiniz. Kartınızın yazma korumasının kapalı olduğuna emin olun.
"https://etcher.balena.io/" adresinden indirebilirsiniz. Her işletim sistemini destekliyor. Teorik olarak USB ile de aynı işlemi yapabilirsiniz fakat her cihaz USB'yi boot edilebilir şekilde algılamıyor ve USB girişi uzun süre üzerinde okuma yazma yapılırsa ısınmaya sebep olabiliyor. Bu yüzden SD Kart üzerinden sistemi ayağa kaldırmanızı tavsiye ederim. Bu yazılım çok basit bir arayüze sahip. Önce yazdırmak istediğimiz imajı seçip ardından ilgili diski seçiyoruz. Eğer imajı ".xz .gz" gibi bir halde indirdiyseniz ve hata alıyorsanız 7-Zip ile imajı dosyaya çıkarıp tekrar deneyebilirsiniz. Yüklendikten sonra Verify kısmını bekleminizi tavsiye ederim. İşletim sistemlerinde dosya bütünlüğü kurulum aşamasında hata çıkmaması için önemlidir.

![](image.png)

Kurulum tamamlandıktan sonra Windows "biçimlendirmeniz gerekiyor" uyarısı verebilir, önemli değil. Kartı çıkarıp tekrar takın. 

1. Ardından S905W işlemci kullandığım için "u-boot-s905x-s912" dosyasını u-boot.ext olarak adlandırdım. Burada kendi işlemciniz için birçok farklı yöntem olabilir. 

2. Daha sonra /extlinux/extlinux.conf dosyasını not defteri ile düzenliyoruz. 
fdt /dtb/amlogic/meson-gxl-s905w-p281.dtb satırını ekliyoruz ve eğer varsa diğer FDT satırlarını yorum satırı yapıyoruz ve kaydediyoruz. Yine cihazınıza göre bu kısım değişiklik gösterecektir.

```
label Armbian_community
   kernel /Image
   initrd /uInitrd
   fdt /dtb/amlogic/meson-gxl-s905w-p281.dtb
   append root=UUID=xxx rootflags=data=writeback console=ttyAML0, 115200n8 console=tty0 rw 
no_console_suspend consoleblank=0 fsck.fix=yes fsck.repair=yes net.ifnames=0 splash plymouth.ignore-serial-consoles
```

Örnek `extlinux.conf` bu şekilde, UUID kısmında da başka bir değer olmalı.

**Cihazda 2GB RAM olmasına rağmen 1GB olarak çalışıyor. Bunun sebebi bu aşamada eksik yapılandırma yapmış olmam veya yanlış DTB dosyası ile çalıştırmam olabilir. Şimdilik 1 GB olarak kullanmaya devam ediyorum daha sonra bu sorunu çözeceğim.**

## İlk Çalıştırma

SD Kartı Android Box'a yerleştirdikten sonra,

### Reset butonunuz varsa

İşiniz çok basit. Çoğu cihazda SD kartını yerleştirdikten sonra reset ve power butonuna basılı tutarak cihazın SD karttan açılması tetikleniyor ve bu sayede cihaz SD kart üzerinden boot oluyor.

### Reset butonunuz yoksa

Önce birkaç farklı yöntem denesem de maalesef çalışmadı. Bu yöntemlerden biri Android uygulamaları arasında bulunan "Run Update & Backup" uygulaması ile "Select" kısmından SD Kartı seçerek "aml_autoscript.zip" dosyasını çalıştırmak. Zip'ten çıkararak da deneyebilirsiniz. Bu yöntem çalışmadı. Daha sonra cihazı normal şekilde Android olarak başlattım. Android 11 yüklü şekilde gayet stabil çalışıyor. 
Jack Palevich'e ait olan en popüler Terminal Emulator'ü "https://www.apkmirror.com/apk/jack-palevich/terminal-emulator/" adresinden indirdim ve USB'ye kopyaladım. Android uygulamalar arasında "AppInstall" isimli uygulamayı açtım. Yoksa dosya yöneticisinden de aynı şekilde yükleyebilirsiniz. Buradan APK dosyasını yükledim. Terminal Emulatoru açtım ve konsolda kullanıcı adın olarak "p281" yazıyordu. Bu aslında cihazın hangi chipsete sahip olduğunu da açıklıyor. 

Konsola `reboot update` yazdım ve enter'a bastım.

Cihaz SD kart üzerinden yeniden başladı. Eğer dosyaları doğru yapılandırdıysanız doğrudan Armbian Linux komut satırı ekrana gelmeli.

![](image-1.png)
![](image-2.png)

İlk çalıştırmada kullanıcı adı, şifre, kablosuz internet kullanımı, dil ve klavye dizilimi belirleme gibi sorular soruyor. Bu adımda Türkçe (tr_TR.UTF-8) için 305 yazıp devam edebilirsiniz. Kablosuz sorusuna "n" diyerek hayır cevabı verdim çünkü cihazı kablo ile modeme bağlayarak kullanacağım. Kurulum adımları tamamlandığında yeniden başlayabilir. Daha sonra giriş bilgilerini girdiğiniz karşınıza Armbian'ın karşılama ekranı çıkacak.

![](image-3.png)

Bu aşamadan sonra cihazın kendi depolama kısmına Armbian'ı kalıcı olarak yüklemeke isterseniz "install-aml.sh" ile devam edebilirsiniz fakat ben cihazı brick etme ihtimaline karşı şimdilik sadece SD kart üzerinden çalıştararak devam edeceğim. Çünkü cihazı geriye döndürmek için satıcı firma tarafından mevcut bir dağıtımı yok. 

![](image-4.png)

## Tekrar Android'e Geçmek & Cihazı Kapatmak & Yeniden Başlatmak

1. Cihazı `(sudo eğer root değilseniz) shutdown -h now` komutuyla kapattıktan sonra SD kartı çıkarın ve Android olarak kullanmaya devam edebilirsiniz. Tekrar çalıştırmak istediğinizde yine Terminal Emulator'den aynı şekilde başlatabilirsiniz. 

2. SD kart takılıyken cihazı kapatıp kumandadan tekrar güç tuşuna bastığımda yine Armbian olarak açılıyor.

3. Cihazı `reboot` komutu ile yeniden başlattığımda da aynı şekilde Armbian olarak çalışmaya devam ediyor.

## SSH ile Bağlanma & İlk Yapılandırmalar

Cihazı modeme bağladıktan sonra "ip a" komutuyla IP alıp almadığını kontrol ediyoruz. Genelde "eth0" adındaki arayüz ile fiziksel etherneet portu çalışır. İnternete bağlandıktan sonra "apt update && apt upgrade" ile güncellemeleri yapıyoruz. SSH servisi genelde yüklü ve açık gelir. "ss -tuln" komutuyla açık portları listeliyoruz.

`tcp LISTEN 0 4096 *:22 *:* `

gibi 22 (SSH) portu ile alakalı bir satır "LISTEN" modunda olmalı. 

`systemctl status ssh.service` (veya sshd) ile SSH servisinin durumunu kontrol ediyoruz.

```
root@aml-s9xx-box:~# systemctl status ssh.service
● ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/usr/lib/systemd/system/ssh.service; enabled; preset: enabled)
     Active: active (running) 
```
şeklinde gözükmeli.

Aynı modeme bağlı bilgisayarınızda Terminal açarak
"ssh kullanıcıadı@IP" şeklinde bağlantıyı başlatıyoruz.

`ssh root@192.168.1.10` 

Tek seferlik çıkan soruya yes diyerek devam edin. 

Bu adımdan sonra cihaza ekran bağlamadan devam edebiliriz. 

Eğer root kullanıcı olarak giriş yaptıysanız komutların başına `sudo` yazmadan kullanabilirsiniz.


### Armbian GPG Anahtar Sorununu Çözme

`apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 93D6889F9F0E78D5`

ile `apt install` veya `update` komutlarında hata çıkarsa bunu giderebiliriz.

### Repository (Depo) Güncelleme

Cihazın internet hızını ve gecikme süresini ölçmek için Ookla Speedtest kurmak istedim.

`curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash`

ile bir dizine indirdim. Daha sonra apt install speedtest ile yüklemek istediğimde 
"E: Unable to locate package speedtest" hatası aldım.

Bazen `apt update` ile çözülse de bu sefer çözülmedi.

İlgili repoları şu şekilde değiştirdim.

`cat /etc/apt/sources.list.d/ookla_speedtest-cli.list`

Çıktı şöyle olmalı:
```
deb [signed-by=/etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg] https://packagecloud.io/ookla/speedtest-cli/ubuntu/ noble main
deb-src [signed-by=/etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg] https://packagecloud.io/ookla/speedtest-cli/ubuntu/ noble main
```

`nano /etc/apt/sources.list.d/ookla_speedtest-cli.list` ile düzenlemek için açıyoruz.

```
deb [signed-by=/etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg] https://packagecloud.io/ookla/speedtest-cli/ubuntu/ jammy main
deb-src [signed-by=/etc/apt/keyrings/ookla_speedtest-cli-archive-keyring.gpg] https://packagecloud.io/ookla/speedtest-cli/ubuntu/ jammy main
```

"noble" kısımlarını "jammy" olarak değiştirip CTRL + X, enter ile kaydediyoruz.

Daha sonra tekrar yüklemeyi deneyin.

### RAM Kullanımı & Swap Alanını Kapatma

Anlık RAM kullanımını görmek için `free -h` yazdım.

```
root@aml-s9xx-box:~# free -h
               total        used        free      shared  buff/cache   available
Mem:           917Mi       192Mi       607Mi       3.8Mi       191Mi       725Mi
Swap:          458Mi          0B       458Mi
```

Eğer cihazda çok RAM tüketen bir işlem yapmayacaksanız SD kartın sağlığı ve kararlılığı (okuma & yazma hızları) açısından daha sürdürülebilir olması için Swap alanını kapatabilirsiniz.

Cihazda otomatik olarak açık gelen Swap alanını görüntülemek için bu komutu yazdım.
```
root@aml-s9xx-box:~# swapon --show
NAME       TYPE        SIZE USED PRIO
/dev/zram0 partition 458.8M   0B    5
```

Bu ayrılmış alanı kapatmak için `swapoff /dev/zram0` yazıyoruz. 
Daha sonra tekrar açmak isterseniz `swapon /dev/zram0` uygulayabilirsiniz.

Eğer /swapfile dosyası hiç oluşturulmadıysa veya silindiyse, önce onu oluşturmanız gerekiyor:
1. Uygun boyutta bir dosya oluşturun (örneğin 1GB için)
sudo fallocate -l 1G /swapfile
Veya dd komutuyla (daha yavaş olabilir):
sudo dd if=/dev/zero of=/swapfile bs=1M count=1024

2. Dosya izinlerini ayarlayın (güvenlik için)
sudo chmod 600 /swapfile

3. Dosyayı swap alanı olarak biçimlendirin
sudo mkswap /swapfile

4. Swap'ı etkinleştirin

**Bu Swap alanını her açılışta kapatmak için bir servis çalıştıracağız ve her açılışta bir kez uygulanacak.**

`nano /etc/systemd/system/disable-swap.service` ile bir servis dosyası oluşturuyoruz ve içerisine aşağıdaki servis komutlarını yazıyoruz.

```
[Unit]
Description=Disable Swap on boot (Swap alanını açılışta kapatmak)
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/sbin/swapoff /dev/zram0
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
```

ve ardından şu adımları uyguladım.

```
systemctl daemon-reload     # Yeni servis dosyasını systemd'ye tanıt
systemctl enable disable-swap.service # Her açılışta çalışması için etkinleştir
systemctl start disable-swap.service # Servisi şimdi başlat (test için)
systemctl status disable-swap.service # Durumunu kontrol ettim.
```

Test etmek için `reboot` yazarak yeniden başlatın ve `free -h` ile kontrol edin.

```
free -h
               total        used        free      shared  buff/cache   available
Mem:           917Mi       214Mi       577Mi       3.9Mi       199Mi       703Mi
Swap:             0B          0B          0B
```

Swap alanı başarıyla kapatıldı.

### WLAN Arayüzlerini Kapatmak

Cihazda fazladan enerji tüketebilecek Wlan arayüzlerini kapatmak için (eğer açıksa) `rfkill list` komutuyla kontrol ediyoruz.
```
root@aml-s9xx-box:~# rfkill list
0: phy0: Wireless LAN
        Soft blocked: no
        Hard blocked: no
1: phy1: Wireless LAN
        Soft blocked: no
        Hard blocked: no
```

`rfkill block wifi` komutundan sonra tekrar kontrol et.

```
root@aml-s9xx-box:~# rfkill list
0: phy0: Wireless LAN
        Soft blocked: yes
        Hard blocked: no
1: phy1: Wireless LAN
        Soft blocked: yes
        Hard blocked: no
```

Bu sayede yazılımsal olarak engelledik.

### Sıcaklık ve Kaynak Tüketimi Takibi

`apt install lm-sensors`

`sensors-detect`

komutlarını yazdıktan sonra sorulara varsayılan (veya) cevapları vererek tüm donanımları taramasını, uygun kerneli bulmasını sağlıyoruz.

```Some south bridges, CPUs or memory controllers contain embedded sensors.
Do you want to scan for them? This is totally safe. (YES/no): yes
modprobe: FATAL: Module cpuid not found in directory /lib/modules/6.12.31-current-meson64
Failed to load module cpuid.
```

hatası aldım ve "Yes" ile devam ediyorum. İhtiyacımız olan sadece CPU sıcaklığı.

`sensors` yazarak cihazdaki anlık sensörleri ve sıcaklıklarını listeliyoruz.

```
root@aml-s9xx-box:~# sensors
scpi_sensors-isa-0000
Adapter: ISA adapter
aml_thermal:  +50.0°C
```
Buradaki değer CPU'ya ait.

`apt install htop` ile htop (Terminal süreç yöneticisi uygulaması) yüklüyoruz.

Cihazın CPU ve RAM kullanımlarını ve sıcaklıklarını istediğiniz zaman pratik ve anlık olarak izlemek için iki terminal açıyoruz. 

birinde `htop` diğerinde `watch -n 1 sensors` çalıştırıyoruz. Cihazın anlık yükünü bu terminaller ile takip edebilirsiniz.

```
Every 1.0s: sensors   
scpi_sensors-isa-0000
Adapter: ISA adapter
aml_thermal:  +50.0°C
```

> `apt install neofetch` veya git clone ile indirip kurulum yaptıktan sonra

![](image-6.png)

### Diğer Opsiyonel Yapılandırmalar

- Kullanıcı adı, hostname değiştirilebilir
- Sudo komutu yetkilendirilmesi düzeltilebilir
- Fail2Ban kurulumu
- SSH portunu değiştirme
- UFW güvenlik duvarı yapılandırması
- Root girişi devre dışı bırakma
- CPU frekans ölçeklemesi (`cpufrequtils` veya `cpupower-gui` ile)
- Tailscale kurulumu ile uzaktan erişim

## Sonuç ve Kullanım Senaryoları

Sonuç olarak düşük enerji tüketen, stabil bir şekilde kesintisiz çalışabilecek ve sınırlı kaynaklarına rağmen birçok servisi çalıştırabileceğiniz bir sunucu kurmuş olduk. Bu kaynakları göz önünde bulundurarak bu sunucuya kullanım amacınıza göre yapılandırabilirsiniz.

- Pi-hole: Ağınızdaki reklamları ve izleyicileri engellemek için DNS tabanlı bir engelleyici.
- Samba veya NFS Sunucusu: Yerel ağınızda dosya paylaşımı için.
- Medya Sunucusu: Plex, Emby, Jellyfin gibi yazılımlarla kendi medya sunucunuzu kurabilirsiniz (TX3 Mini'nin performansı video transcoding için sınırlı olabilir, direct play daha uygun).
- Nextcloud/OwnCloud: Kendi kişisel bulut depolama ve senkronizasyon çözümü.
- Vaultwarden: Bitwarden'ın daha hafif bir Rust implementasyonudur. Kendi şifre yöneticinizi barındırmak için.
- Home Assistant: Akıllı ev otomasyonu için.
- Docker Kurulumu: Birçok servisi izole konteynerlarda çalıştırmak için çok kullanışlıdır. 
- Home Server: YunoHost, CasaOS gibi, genel kullanım amaçlı veya ufak projelerinizi çalıştırmak ve denemek için kullanılabilir.

## Yararlandığım Diğer Kaynaklar

- https://github.com/armbian/build
- https://www.armbian.com/orange-pi-zero-3/
- https://github.com/warpme/minimyth2/tree/master/script/bootloaders
- https://forum.armbian.com/topic/16976-status-of-armbian-on-tv-boxes-please-read-first
- https://i12bretro.github.io/tutorials/0316.html
- https://forum.armbian.com/topic/33676-installation-instructions-for-tv-boxes-with-amlogic-cpus
- https://forum.armbian.com/topic/49508-install-bookworm-6663-on-x96q-pro-h728/