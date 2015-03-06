# ydcmd

[English](https://github.com/abbat/ydcmd/blob/master/README.en.md) | [Русский](https://github.com/abbat/ydcmd/blob/master/README.md)

[REST API](http://api.yandex.com.tr/disk/api/concepts/about.xml) vasıtasıyla bulut depolama [Yandex.Disk](https://disk.yandex.com.tr/) ile etkileşim için Linux/FreeBSD'nin komut satırı istemcisidir.

## İndirme / Kurma

* [Debian, Ubuntu](http://software.opensuse.org/download.html?project=home:antonbatenev:ydcmd&package=ydcmd)
* [Fedora, openSUSE, CentOS](http://software.opensuse.org/download.html?project=home:antonbatenev:ydcmd&package=ydcmd)
* [Ubuntu PPA](https://launchpad.net/~abbat/+archive/ubuntu/ydcmd) - `ppa:abbat/ydcmd`
* [Arch AUR](https://aur.archlinux.org/packages/ydcmd/) (ayrıca bkz. [AUR Helpers] (https://wiki.archlinux.org/index.php/AUR_Helpers_(Türkçe)))
* Kaynak kodundan:

```
$ git clone https://github.com/abbat/ydcmd.git
$ sudo cp ydcmd/ydcmd.py /usr/local/bin/ydcmd
```

## Çalışmaya hazırlık

İstemcinin çalışması için OAuth ayıklama belirteci gereklidir. Almak için, [Yandex'ten uygulamayı kaydediniz](https://oauth.yandex.com.tr/client/new):

* `Adı` - `ydcmd` (isteğe bağlı olabilir)
* `İzinler` - `Yandex.Disk REST API`
* `Geliştirme için istemci` - onay kutusunu seçmek.

Uygulamayı kaydettikten sonra `uygulama id'sini` kopyalayınız ve bağlantıyı izleyiniz:

* `https://oauth.yandex.com.tr/authorize?response_type=token&client_id=<id_uygulama>`

Erişim sağlandıktan sonra hizmet sizi şu bağlantıya yönlendirir:

* `https://oauth.yandex.com.tr/verification_code?dev=True#access_token=<belirteç>`

''belirteç'' değeri gereklidir. Daha fazla bilgi almak için bağlantı [elle hata ayıklama belirteci alma](http://api.yandex.com.tr/oauth/doc/dg/tasks/get-oauth-token.xml).

## Çalıştırma

Kısa yardım bilgilerine komut satırı içerisinde komut dosyası çalıştırıp paremetresiz ya da `help` komutunu girerek erişebilirsiniz. Genel çağırma biçimi:

```
ydcmd [komut] [seçenekler] [argümanlar]
```

**Komutlar**:

* `help` - uygulama komutları ve seçenekleri hakkında kısa bilgi alma;
* `ls` - dosya ve dizinlerin listesini alma;
* `rm` - dosya veya dizin silme;
* `cp` - dosya veya dizin kopyalama;
* `mv` - dosya veya dizin taşıma;
* `put` - dosya veya dizini depoya yükleme;
* `get` - dosya veya dizini depodan alma;
* `mkdir` - dizin oluşturma;
* `stat` - nesne hakkında meta-bilgi alma;
* `info` - depo hakkında meta-bilgi alma;
* `last` - son yüklenen dosyalar hakkında meta-bilgi alma;
* `share` - yayın nesnenin (daha doğrudan bağlantılar);
* `revoke` - kapanış erişim yayımlanmış, daha önce nesne;
* `du` - dosyaların hafızada kapladığı alanı hesaplama;
* `clean` - dosya ve dizinleri temizleme;
* `token` - almak OAuth token uygulaması için.

**Seçenekler**:

* `--timeout=<N>` - ağ bağlantısı kurmak için zaman aşımı (saniye);
* `--retries=<N>` - hata kodu almadan önce API yöntemini çağırma denemelerinin sayısı;
* `--delay=<N>` - api metodunu çağırma denemeleri arasındaki zaman aşımı (saniye);
* `--limit=<N>` - dosya ve dizinlerin listesini alma metodunun bir çağrısı ile geri dönen öge sayısı;
* `--token=<S>` - oauth belirteci (yapılandırma dosyasının içinde ya da ortam değişkeni ile `YDCMD_TOKEN` güvenlik hedefleri için belirtilmiş olmalı);
* `--quiet` - hatta raporu önleme, işlem başarısının sonucu dönüş kodu ile belirlenir;
* `--verbose` - genişletilmiş bilgileri görüntüleme;
* `--debug` - hata ayıklama bilgisi görüntüleme;
* `--chunk=<N>` - girdi/çıktı işlemleri için bilgi bloğunun boyutu (KB);
* `--ca-file=<S>` - güvenilir sertifika merkezlerinin sertifikaları ile dosya adı (değer boş ise, sertifika onayı gerçekleştirilemez);
* `--ciphers=<S>` - şifreleme algoritmaları dizisi (bak [ciphers(1)](https://www.openssl.org/docs/apps/ciphers.html));
* `--version` - print version and exit.

### Dosya ve dizinlerin listesini alma

```
ydcmd ls [seçenekler] [disk:/nesne]
```

**Seçenekler**:

* `--human` - insan tarafından okunabilir türde dosyanın boyutunu görüntüleme;
* `--short` - ek bilgiler olmadan dosya ve dizinlerin listesini görüntüleme (satır başına bir ad);
* `--long` - genişletilmiş liste gösterme (oluşturma zamanı, değişiklik zamanı, boyut, dosya adı).

Eğer hedef nesne belirtilmemişse, deponun kök dizini kullanılacaktır.

### Dosya veya dizin silme

```
ydcmd rm disk:/nesne
```

**Seçenekler**:

* `--poll=<N>` - asenkron işlem sırasında durum kontrolleri arasındaki süre (saniye);
* `--async` - işlem sonlandırmasını (`poll`) beklemeyip komutunu çalıştırma.

Dosyalar kalıcı olarak silinir. Dizinler özyinelemeli silinir (alt dosya ve dizinler dahil).

### Dosya veya dizin kopyalama

```
ydcmd cp disk:/nesne1 disk:/nesne2
```

**Seçenekler**:

* `--poll=<N>` - asenkron işlem sırasında durum kontrolleri arasındaki süre (saniye);
* `--async` - işlem sonlandırmayı beklemeden komut (`poll`) çalıştırma.

İsim çakışması durumunda, dizinler ve dosyalar üzerine yazılacak. Dizinler özyinelemeli kopyalanır (alt dosya ve dizinler dahil).

### Dosya veya dizin taşıma

```
ydcmd mv disk:/nesne1 disk:/nesne2
```

**Seçenekler**:

* `--poll=<N>` - asenkron işlem sırasında durum kontrolleri arasındaki süre (saniye);
* `--async` - işlem sonlandırmayı beklemeden komut (`poll`) çalıştırma.

İsim çakışması durumunda, dizinler ve dosyalar üzerine yazılacak.

### Depoya dosya yükleme

```
ydcmd put <dosya> [disk:/nesne]
```

**Seçenekler**:

* `--rsync` - depoda, dosya ve dizinlerin ağaçları ile yerel ağacı senkronize eder;
* `--no-recursion` - avoid descending automatically in directories;
* `--skip-md5` - skip md5 integrity checks;
* `--threads=<N>` - number of worker processes;
* `--iconv=<S>` - try to restore file or directory names from the specified encoding if necessary (for example `--iconv=cp1254`).

Eğer hedef nesne belirtilmemişse, dosya yüklemesi için deponun kök dizini kullanılacaktır. Eğer hedef nesne, dizini ("/" ile biten) belirtirse, kaynak dosyasının adı dizinin adına eklenmiş olacaktır. Eğer hedef nesne varsa, onay istemi olmadan üzerine yazılabilir olacaktır. Sembolik bağlantılar göz ardı edilir.

### Depodan dosya alma

```
ydcmd get <disk:/nesne> [dosya]
```

**Seçenekler**:

* `--rsync` - dosya ve dizinlerin yerel ağaçları ile depo içerisindeki ağacı senkronize eder;
* `--no-recursion` - avoid descending automatically in directories;
* `--skip-md5` - skip md5 integrity checks;
* `--threads=<N>` - number of worker processes.

Eğer hedef dosyasının adı belirtilmemişse, depoda var olan adı kullanılacaktır. Eğer hedef nesne varsa, onay istemi olmadan üzerine yazılabilir olacaktır.

### Dizin oluşturma

```
ydcmd mkdir disk:/yol
```

### Nesne hakkında meta-bilgi alma

```
ydcmd stat [disk:/nesne]
```

Eğer hedef nesne belirtilmemişse, deponun kök dizini kullanılacaktır.

### Depo hakkında meta-bilgi alma

```
ydcmd info
```

**Seçenekler**:

* `--long` - İnsan tarafından okunabilir türde göstermek yerine bayt'larla göstermek;

### Son yüklenen dosyalar hakkında meta-bilgi alma

```
ydcmd last [N]
```

**Seçenekler**:

* `--human` - insan tarafından okunabilir türde dosyanın boyutunu görüntüleme;
* `--short` - ek bilgiler olmadan dosyaların listesini görüntüleme (satır başına bir ad);
* `--long` - genişletilmiş liste gösterme (oluşturma zamanı, değişiklik zamanı, boyut, dosya).

Eğer N argüman belirtilmemişse, REST API'nin varsayılan değeri kullanılacaktır.

### Yayın nesne

```
ydcmd share disk:/nesne
```

Komut verir path ve url nesne.

### Erişim kapatma

```
ydcmd revoke disk:/nesne
```

### Kullanılan disk alanı değerlendirmesi

```
ydcmd du [disk:/nesne]
```

**Seçenekler**:

* `--depth=<N>` - seviye N'e kadar olan dizinlerin boyutlarını göstermek;
* `--long` - İnsan tarafından okunabilir türde göstermek yerine bayt'larla göstermek;

Eğer hedef nesne belirtilmemişse, deponun kök dizini kullanılacaktır.

### Dosya ve dizinleri temizleme

```
ydcmd clean <seçenekler> [disk:/nesne]
```

**Seçenekler**:

* `--dry` - silmek yerine, silinecek nesnelerin listesini göstermek;
* `--type=<S>` - silinecek nesnelerin türü (`file` - dosyalar, `dir` - dizinler, `all` - hepsi);
* `--keep=<S>` - kaydedilmesi gereken nesnelerin seçim kriterleri:
* Verinin silinmesi gereken **tarihe kadar** seçilmesi için ISO formatındaki tarih satırı kullanılabilir (örneğin `2014-02-12T12:19:05+04:00`);
* Göreceli zamanı seçmek için sayı ve boyut kullanılabilir (örneğin, `7d`, `4w`, `1m`, `1y`);
* Kopya sayısını seçmek için, boyut olmadan sayı kullanılabilir (örneğin, `31`).

Eğer hedef nesne belirtilmemişse, deponun kök dizini kullanılacaktır. Nesneler değiştirme tarihine göre (oluşturma tarihi ile değil) sıralanır ve filtrelenir.

## Yapılandırma

Kolaylık sağlamak için `~/.ydcmd.cfg` isimli bir yapılandırma dosyası oluşturmak ve bu dosyaya `0600` veya `0400` izinlerini vermek tavsiye edilir. Dosya biçimi:

```
[ydcmd]
# yorum
<option> = <value>
```

Örneğin:

```
[ydcmd]
token   = 1234567890
verbose = yes
ca-file = /etc/ssl/certs/ca-certificates.crt
```

## Çevre değişkenleri

* `YDCMD_TOKEN` - oauth belirteci, `--token` seçeneği üzerinde önceliğe sahiptir;
* `SSL_CERT_FILE` - güvenilir sertifika merkezlerinin sertifikaları ile dosya adı, `--ca-file` seçeneği üzerinde önceliğe sahiptir.

## Çıkış kodu

Otomatik modda çalışırken (cron), komut çalışmasının sonucunu almak yararlı olabilir:

* `0` - başarılı tamamlama;
* `1` - genel uygulama hatası;
* `4` - durum kodu HTTP-4xx (istemci hatası);
* `5` - durum kodu HTTP-5xx (sunucu hatası).

## Çeviri

Tatyana Pekhas <<tatyana-zlobina@mail.ru>>
