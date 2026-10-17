#!/usr/bin/env python3
"""QWEROSY Toolkit — Defensive Security Edition.

eğitim için savunma odaklı terminal aracı.
Yalnızca Python 3 standart kütüphanesini kullanır.

Sürüm 1.7: Brute-force mükerrer alarm tespiti düzeltildi, _hedef_ayikla 
fonksiyonuna IPv6 zone ID desteği eklendi ve port taşma (OverflowError) 
korumaları tamamlandı.

Etik kullanım: Port tarama, yol kontrolü, başlık analizi ve ağ erişim testleri
yalnızca sahip olunan veya açıkça test izni verilen sistemlerde yapılmalıdır.
"""

from __future__ import annotations

import errno
import getpass
import hashlib
import ipaddress
import os
import re
import shutil
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import TextIO

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

ARAC_ADI = "QWEROSY TOOLKIT"
ARAC_SURUM = "Defensive Security Edition 1.7"

PORT_LISTESI: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080
)

YOL_LISTESI: tuple[str, ...] = (
    "/admin",
    "/login",
    "/dashboard",
    "/backup",
    "/backup.zip",
    "/wp-admin",
    "/wp-login.php",
    "/config",
    "/config.php",
    "/api",
    "/api/docs",
    "/robots.txt",
    "/sitemap.xml",
    "/phpmyadmin",
    "/uploads",
    "/images",
    "/assets",
    "/static",
    "/server-status",
    "/.well-known/",
    "/register",
    "/health",
    "/status",
    "/docs",
    "/test",
)

SQLI_DESENLERI: tuple[tuple[str, str], ...] = (
    ("' OR '1'='1", r"(?i)'\s*or\s+'1'\s*=\s*'1"),
    ("UNION SELECT", r"(?i)\bunion\s+select\b"),
    (";--", r";\s*--"),
    ("SQL Yorum Sızıntısı", r"(?i)(?:'|\bselect\b|\bunion\b|\bfrom\b)\s*--"),
    ("xp_cmdshell", r"(?i)\bxp_cmdshell\b"),
)

LOG_SATIR_DESENI = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<zaman>[^\]]+)\]\s+"
    r'"(?P<metod>\S+)\s+(?P<yol>\S+)(?:\s+(?P<protokol>[^"]*))?"\s+'
    r"(?P<kod>\d{3})"
)

HTTP_ZAMAN_ASIMI = 5.0
DIZIN_ISTEK_ARALIGI = 0.12
PORT_ZAMAN_ASIMI = 1.0
TCP_ZAMAN_ASIMI = 3.0
MAX_LOG_BOYUTU = 25 * 1024 * 1024  # 25 MiB

# Windows WSA hata kodları
WSAETIMEDOUT = 10060
WSAEWOULDBLOCK = 10035
WSAECONNREFUSED = 10061
WSAHOST_UNREACHABLE = 10065
WSAENETUNREACH = 10051

_ANSI_AKTIF = False


class Renkler:
    """ANSI renk kodlarını tek yerden yönetir."""

    SIFIRLA = "\033[0m"
    KALIN = "\033[1m"
    KIRMIZI = "\033[31m"
    YESIL = "\033[32m"
    SARI = "\033[33m"
    MAVI = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRI = "\033[90m"
    BEYAZ = "\033[97m"


# ---------------------------------------------------------------------------
# Terminal / renk yardımcıları
# ---------------------------------------------------------------------------

def _windows_ansi_etkinlestir() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        yeni = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return kernel32.SetConsoleMode(handle, yeni) != 0
    except (AttributeError, OSError, ValueError):
        return False


def renk_destegi_ayarla() -> None:
    global _ANSI_AKTIF
    if os.environ.get("NO_COLOR"):
        _ANSI_AKTIF = False
        return
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        _ANSI_AKTIF = False
        return
    if os.name == "nt":
        _ANSI_AKTIF = _windows_ansi_etkinlestir()
        return
    _ANSI_AKTIF = True


def renkli_yaz(
    metin: str,
    renk: str = "",
    *,
    son: str = "\n",
    dosya: TextIO | None = None,
    kalin: bool = False,
) -> None:
    hedef = dosya if dosya is not None else sys.stdout
    if _ANSI_AKTIF and (renk or kalin):
        parcalar = []
        if kalin:
            parcalar.append(Renkler.KALIN)
        if renk:
            parcalar.append(renk)
        cikti = f"{''.join(parcalar)}{metin}{Renkler.SIFIRLA}"
    else:
        cikti = metin
    try:
        print(cikti, end=son, file=hedef)
    except UnicodeEncodeError:
        print(metin.encode("ascii", "replace").decode("ascii"), end=son, file=hedef)


def etiket(kod: str, mesaj: str, renk: str = "") -> None:
    if not renk:
        renk = {
            "[+]": Renkler.YESIL,
            "[-]": Renkler.GRI,
            "[!]": Renkler.SARI,
            "[~]": Renkler.CYAN,
            "[i]": Renkler.MAVI,
        }.get(kod, "")
    renkli_yaz(f"{kod} {mesaj}", renk)


def terminal_genisligi() -> int:
    try:
        genislik = shutil.get_terminal_size(fallback=(80, 24)).columns
    except OSError:
        genislik = 80
    return max(60, min(genislik, 100))


def cerceve_ciz(satirlar: list[str], genislik: int | None = None) -> None:
    w = genislik if genislik is not None else min(terminal_genisligi(), 56)
    ic = w - 2
    renkli_yaz("╔" + ("═" * ic) + "╗", Renkler.CYAN, kalin=True)
    for satir in satirlar:
        if satir == "--":
            renkli_yaz("╠" + ("═" * ic) + "╣", Renkler.CYAN)
            continue
        if satir.startswith("^"):
            metin = satir[1:][:ic]
            pad_sol = max(0, (ic - len(metin)) // 2)
        else:
            metin = satir[:ic]
            pad_sol = 1
        pad_sag = max(0, ic - pad_sol - len(metin))
        renkli_yaz(
            "║" + (" " * pad_sol) + metin + (" " * pad_sag) + "║",
            Renkler.CYAN,
        )
    renkli_yaz("╚" + ("═" * ic) + "╝", Renkler.CYAN, kalin=True)


def bolum_basligi(baslik: str) -> None:
    w = terminal_genisligi()
    renkli_yaz("")
    renkli_yaz(f"── {baslik} " + ("─" * max(4, w - len(baslik) - 4)), Renkler.MAGENTA, kalin=True)


def etik_uyari_goster() -> None:
    renkli_yaz("")
    cerceve_ciz(
        [
            f"^{ARAC_ADI}",
            f"^{ARAC_SURUM}",
            "--",
            "  Yalnızca eğitim ve savunma amaçlıdır",
        ]
    )
    renkli_yaz("")
    etiket("[i]", "Kullanım sorumluluğu size aittir.")
    renkli_yaz("")


# ---------------------------------------------------------------------------
# Girdi / menü yardımcıları
# ---------------------------------------------------------------------------

def girdi_al(istem: str, *, zorunlu: bool = True, kucult: bool = False) -> str | None:
    while True:
        try:
            deger = input(istem)
        except EOFError:
            renkli_yaz("")
            etiket("[!]", "Girdi sonu (EOF) algılandı.")
            return None
        deger = deger.strip()
        if kucult:
            deger = deger.casefold()
        if deger or not zorunlu:
            return deger
        etiket("[!]", "Boş girdi kabul edilmez. Lütfen bir değer yazın.")


def evet_hayir(istem: str) -> bool:
    yanit = girdi_al(f"{istem} [e/H]: ", zorunlu=False, kucult=True)
    if yanit is None:
        return False
    return yanit in {"e", "evet", "y", "yes"}


def ana_menuye_don() -> None:
    renkli_yaz("")
    try:
        input("Ana menüye dönmek için ENTER'a basın...")
    except (KeyboardInterrupt, EOFError):
        renkli_yaz("")
        etiket("[i]", "Ana menüye dönülüyor.")


def menu_goster() -> None:
    cerceve_ciz(
        [
            f"^{ARAC_ADI}",
            f"^{ARAC_SURUM}",
            "--",
            "  1. Port Tarayıcı",
            "  2. Dizin ve Dosya Bulucu",
            "  3. Log Analiz Aracı",
            "  4. Şifre ve Hash Analizi",
            "  5. DNS ve Host Erişim Kontrolü",
            "  6. HTTP Güvenlik Başlıkları Denetimi",
            "  0. Çıkış",
        ]
    )


# ---------------------------------------------------------------------------
# Ağ yardımcıları
# ---------------------------------------------------------------------------

def _hedef_ayikla(girdi: str) -> tuple[str, int | None]:
    """Girdi içinden hostname/IP (zone ID korumalı) ve port ayıklar.

    Returns:
        (hedef_str, port_int_veya_None)
    """
    metin = girdi.strip()
    if not metin:
        return "", None

    if "://" in metin:
        try:
            parca = urllib.parse.urlsplit(metin)
            return (parca.hostname or "").strip(), parca.port
        except ValueError:
            return "", None

    metin = re.split(r"[/?#]", metin, maxsplit=1)[0].strip()
    if not metin:
        return "", None

    # Köşeli IPv6: [2001:db8::1%eth0] veya [2001:db8::1]:443
    if metin.startswith("["):
        kapanis = metin.find("]")
        if kapanis == -1:
            return "", None
        host = metin[1:kapanis]
        kuyruk = metin[kapanis + 1:]
        port = None
        if kuyruk.startswith(":"):
            p_str = kuyruk[1:]
            if p_str.isdigit():
                p_val = int(p_str)
                if 1 <= p_val <= 65535:
                    port = p_val
        try:
            # Zone ID (%eth0) varsa ayrıştırarak doğrula
            temiz_host = host.split("%")[0]
            ipaddress.IPv6Address(temiz_host)
            return host, port
        except ValueError:
            return "", None

    # Hostname:port veya IPv4:port
    port = None
    if metin.count(":") == 1:
        host, p_str = metin.rsplit(":", 1)
        if p_str.isdigit():
            p_val = int(p_str)
            if 1 <= p_val <= 65535:
                host = host.strip()
                port = p_val
            else:
                return "", None

    return metin, port


def ip_adresi_mi(deger: str) -> bool:
    try:
        temiz_ip = deger.split("%")[0]
        ipaddress.ip_address(temiz_ip)
        return True
    except ValueError:
        return False


def hedef_coz(hedef: str) -> tuple[list[tuple[socket.AddressFamily, str]], str | None]:
    # Zone ID içeren adreslerde getaddrinfo hata vermemesi için temizle
    cozum_hedefi = hedef.split("%")[0] if "%" in hedef else hedef
    try:
        bilgiler = socket.getaddrinfo(cozum_hedefi, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as hata:
        return [], f"Hedef çözümlenemedi: {hata.strerror or hata}"
    except (OSError, UnicodeError) as hata:
        return [], f"Hedef doğrulanamadı: {hata}"

    gorulen: set[tuple[int, str]] = set()
    ipv4: list[tuple[socket.AddressFamily, str]] = []
    ipv6: list[tuple[socket.AddressFamily, str]] = []
    for aile, _tur, _proto, _kanon, sockaddr in bilgiler:
        ip = sockaddr[0]
        anahtar = (int(aile), ip)
        if anahtar in gorulen:
            continue
        gorulen.add(anahtar)
        if aile == socket.AF_INET:
            ipv4.append((aile, ip))
        elif aile == socket.AF_INET6:
            ipv6.append((aile, ip))
    return ipv4 + ipv6, None


def port_sonucunu_siniflandir(kod: int) -> str:
    if kod == 0:
        return "acik"
    zaman_asimlari = {
        errno.ETIMEDOUT,
        WSAETIMEDOUT,
        WSAEWOULDBLOCK,
    }
    if hasattr(errno, "EWOULDBLOCK"):
        zaman_asimlari.add(errno.EWOULDBLOCK)
    if hasattr(errno, "EINPROGRESS"):
        zaman_asimlari.add(errno.EINPROGRESS)
    if hasattr(errno, "EAGAIN"):
        zaman_asimlari.add(errno.EAGAIN)
    if kod in zaman_asimlari:
        return "yanit_yok"
    erisilemez = {WSAHOST_UNREACHABLE, WSAENETUNREACH}
    if hasattr(errno, "EHOSTUNREACH"):
        erisilemez.add(errno.EHOSTUNREACH)
    if hasattr(errno, "ENETUNREACH"):
        erisilemez.add(errno.ENETUNREACH)
    if hasattr(errno, "ENETDOWN"):
        erisilemez.add(errno.ENETDOWN)
    if kod in erisilemez:
        return "yanit_yok"
    return "kapali"


def errno_aciklama(kod: int) -> str:
    if kod == 0:
        return "bağlantı kuruldu"
    if kod in {errno.ECONNREFUSED, WSAECONNREFUSED}:
        return "bağlantı reddedildi (port kapalı veya servis yok)"
    if kod in {WSAETIMEDOUT, errno.ETIMEDOUT}:
        return "zaman aşımı (filtre veya yanıt yok)"
    try:
        return os.strerror(kod)
    except (OverflowError, ValueError):
        return f"sistem kodu {kod}"


# ---------------------------------------------------------------------------
# MODÜL 1 — Port Tarayıcı
# ---------------------------------------------------------------------------

def port_tarayici() -> None:
    bolum_basligi("Port Tarayıcı")
    etiket("[i]", "Yalnızca yetkili laboratuvar veya kendi sisteminiz.")
    etiket("[i]", f"Kontrol edilecek portlar: {', '.join(str(p) for p in PORT_LISTESI)}")

    ham = girdi_al("Hedef IP veya hostname: ")
    if ham is None:
        return
    hedef, _ = _hedef_ayikla(ham)
    if not hedef:
        etiket("[!]", "Geçerli bir hedef girilmedi.")
        return

    etiket("[~]", f"{hedef} çözümleniyor...")
    adresler, hata = hedef_coz(hedef)
    if hata or not adresler:
        etiket("[!]", hata or "Hedef için adres bulunamadı.")
        return

    ipv4 = [(a, ip) for a, ip in adresler if a == socket.AF_INET]
    ipv6 = [(a, ip) for a, ip in adresler if a == socket.AF_INET6]
    if ipv4:
        aile, ip = ipv4[0]
        if ipv6:
            etiket("[i]", f"IPv6 adresi de var ({ipv6[0][1]}); taramada IPv4 öncelikli.")
    else:
        aile, ip = ipv6[0]
        etiket("[i]", "IPv4 adresi yok; IPv6 ile devam ediliyor.")

    sonuclar: list[tuple[int, str, str]] = []
    baslangic = time.perf_counter()
    kesildi = False

    try:
        for port in PORT_LISTESI:
            etiket("[~]", f"Port {port} kontrol ediliyor...")
            sock = None
            try:
                sock = socket.socket(aile, socket.SOCK_STREAM)
                sock.settimeout(PORT_ZAMAN_ASIMI)
                if aile == socket.AF_INET6:
                    kod = sock.connect_ex((ip, port, 0, 0))
                else:
                    kod = sock.connect_ex((ip, port))
            except OSError as os_hata:
                sinif = "yanit_yok"
                aciklama = str(os_hata)
                sonuclar.append((port, sinif, aciklama))
                etiket("[!]", f"Port {port:<5} YANIT ALINAMADI — {aciklama}")
                continue
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

            sinif = port_sonucunu_siniflandir(kod)
            aciklama = errno_aciklama(kod)
            sonuclar.append((port, sinif, aciklama))
            if sinif == "acik":
                etiket("[+]", f"Port {port:<5} AÇIK")
            elif sinif == "kapali":
                etiket("[-]", f"Port {port:<5} KAPALI — {aciklama}")
            else:
                etiket("[!]", f"Port {port:<5} YANIT ALINAMADI — {aciklama}")
    except KeyboardInterrupt:
        kesildi = True
        renkli_yaz("")
        etiket("[!]", "Tarama kullanıcı tarafından durduruldu (Ctrl+C).")

    sure = time.perf_counter() - baslangic
    acik = [p for p, s, _ in sonuclar if s == "acik"]
    kapali = [p for p, s, _ in sonuclar if s == "kapali"]
    yanit_yok = [p for p, s, _ in sonuclar if s == "yanit_yok"]

    renkli_yaz("")
    renkli_yaz("Özet rapor", Renkler.KALIN)
    etiket("[i]", f"Hedef hostname : {hedef}")
    etiket("[i]", f"Çözümlenen IP  : {ip}")
    etiket("[i]", f"Kontrol edilen : {len(sonuclar)} / {len(PORT_LISTESI)} port")
    etiket("[+]", f"Açık port      : {len(acik)}" + (f" → {acik}" if acik else ""))
    etiket("[-]", f"Kapalı (doğrulanan) : {len(kapali)}")
    etiket("[!]", f"Yanıt alınamayan    : {len(yanit_yok)}")
    etiket("[i]", f"Geçen süre     : {sure:.2f} saniye")
    if kesildi:
        etiket("[!]", "Özet yalnızca tamamlanan denemeleri içerir (tarama yarıda kesildi).")


# ---------------------------------------------------------------------------
# MODÜL 2 — Dizin ve Dosya Bulucu
# ---------------------------------------------------------------------------

def _url_dogrula(ham: str) -> tuple[str | None, str | None]:
    metin = ham.strip()
    if not metin:
        return None, "Boş URL."
    try:
        parca = urllib.parse.urlparse(metin)
        port = parca.port
    except ValueError as hata:
        return None, f"URL/port geçersiz: {hata}"
    sema = parca.scheme.lower()
    if sema not in {"http", "https"}:
        return None, "Yalnızca http:// veya https:// şemaları kabul edilir."
    if not parca.netloc or not parca.hostname:
        return None, "URL içinde geçerli bir hostname bulunamadı."
    if parca.username is not None or parca.password is not None:
        return None, "Güvenlik için URL içine kullanıcı adı/parola yazılamaz."
    if any(ch.isspace() for ch in parca.netloc):
        return None, "Hostname/port alanında boşluk olamaz."
    if port is not None and not (1 <= port <= 65535):
        return None, "Port 1 ile 65535 arasında olmalıdır."

    host = parca.hostname.rstrip(".")
    if not host:
        return None, "Hostname boş olamaz."
    try:
        ip_obj = ipaddress.ip_address(host.split("%")[0])
        host_norm = ip_obj.compressed
        host_netloc = f"[{host_norm}]" if isinstance(ip_obj, ipaddress.IPv6Address) else host_norm
    except ValueError:
        try:
            host_norm = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None, "Hostname geçerli biçimde kodlanamadı."
        desen = r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*"
        if not re.fullmatch(desen, host_norm):
            return None, "Hostname biçimi geçersiz."
        host_netloc = host_norm

    if port is not None and not ((sema == "http" and port == 80) or (sema == "https" and port == 443)):
        host_netloc = f"{host_netloc}:{port}"
    taban = urllib.parse.urlunparse(
        (sema, host_netloc, parca.path.rstrip("/"), "", "", "")
    )
    return taban, None


def _http_durum_al(url: str) -> tuple[int | None, str]:
    istek = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": "QWEROSY-Toolkit-Edu/1.7 (defensive-lab)",
            "Accept": "*/*",
        },
    )
    try:
        with urllib.request.urlopen(istek, timeout=HTTP_ZAMAN_ASIMI) as yanit:
            kod = getattr(yanit, "status", None) or yanit.getcode()
            try:
                yanit.read(0)
            except OSError:
                pass
            return int(kod), "yanıt alındı"
    except urllib.error.HTTPError as hata:
        kod = int(hata.code)
        try:
            hata.close()
        except OSError:
            pass
        return kod, "HTTPError"
    except ssl.SSLError as hata:
        return None, f"SSL/TLS hatası: {hata}"
    except (socket.timeout, TimeoutError):
        return None, "zaman aşımı"
    except urllib.error.URLError as hata:
        neden = hata.reason
        if isinstance(neden, (socket.timeout, TimeoutError)):
            return None, "zaman aşımı"
        return None, f"bağlantı hatası: {neden}"
    except OSError as hata:
        return None, f"ağ/işletim sistemi hatası: {hata}"


def dizin_bulucu() -> None:
    bolum_basligi("Dizin ve Dosya Bulucu")
    etiket("[i]", "Yetkili laboratuvar veya kendi test ortamınızı kullanın.")
    ham = girdi_al("Tam HTTP veya HTTPS URL: ")
    if ham is None:
        return
    taban, hata = _url_dogrula(ham)
    if hata or taban is None:
        etiket("[!]", hata or "URL doğrulanamadı.")
        return

    bulunan: list[tuple[int, str, str]] = []
    kontrol = 0
    kesildi = False

    try:
        for yol in YOL_LISTESI:
            tam = urllib.parse.urljoin(taban.rstrip("/") + "/", yol.lstrip("/"))
            if yol.endswith("/") and not tam.endswith("/"):
                tam += "/"
            kontrol += 1
            etiket("[~]", f"Kontrol ({kontrol}/{len(YOL_LISTESI)}): {tam}")
            kod, _ = _http_durum_al(tam)
            if kod == 200:
                bulunan.append((kod, "BULUNDU", tam))
                etiket("[+]", f"200 BULUNDU          {tam}")
            elif kod == 403:
                bulunan.append((kod, "ERİŞİM YASAK", tam))
                etiket("[!]", f"403 ERİŞİM YASAK     {tam}")
            time.sleep(DIZIN_ISTEK_ARALIGI)
    except KeyboardInterrupt:
        kesildi = True
        renkli_yaz("")
        etiket("[!]", "Yol kontrolü kullanıcı tarafından durduruldu (Ctrl+C).")

    renkli_yaz("")
    renkli_yaz("Bulunan kaynaklar (200 ve 403)", Renkler.KALIN)
    if bulunan:
        for kod, durum, url in bulunan:
            print(f"  {kod:<6} {durum} — {url}")
    else:
        etiket("[-]", "200 veya 403 dönen yol bulunamadı.")
    etiket("[i]", f"Taranan yol sayısı: {kontrol} / {len(YOL_LISTESI)}")
    if kesildi:
        etiket("[!]", "Tarama yarıda kesildiği için sonuçlar eksik olabilir.")


# ---------------------------------------------------------------------------
# MODÜL 3 — Log analizi
# ---------------------------------------------------------------------------

def ornek_log_olustur(hedef_yol: str) -> bool:
    ornek = """192.0.2.10 - - [16/Oct/2026:12:00:00 +0000] "POST /login HTTP/1.1" 401
192.0.2.10 - - [16/Oct/2026:12:00:15 +0000] "POST /login HTTP/1.1" 401
192.0.2.10 - - [16/Oct/2026:12:00:30 +0000] "POST /login HTTP/1.1" 401
192.0.2.10 - - [16/Oct/2026:12:00:45 +0000] "POST /login HTTP/1.1" 401
198.51.100.20 - - [16/Oct/2026:12:01:00 +0000] "GET /index.html HTTP/1.1" 200
203.0.113.40 - - [16/Oct/2026:12:02:10 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 400
203.0.113.40 - - [16/Oct/2026:12:02:20 +0000] "GET /list?id=1 UNION SELECT username,password FROM users HTTP/1.1" 400
"""
    try:
        with open(hedef_yol, "w", encoding="utf-8", newline="\n") as dosya:
            dosya.write(ornek)
        etiket("[+]", f"Sentetik örnek log yazıldı: {hedef_yol}")
        return True
    except OSError as hata:
        etiket("[!]", f"Dosya yazılamadı: {hata}")
        return False


def _zaman_ayikla(zaman_metni: str) -> datetime | None:
    for bicim in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            dt = datetime.strptime(zaman_metni, bicim)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def log_analiz() -> None:
    bolum_basligi("Log Analiz Aracı")
    yol = girdi_al("Log dosyası yolu: ")
    if yol is None:
        return
    yol = os.path.expanduser(yol)

    if not os.path.isfile(yol):
        etiket("[!]", f"Dosya bulunamadı: {yol}")
        if evet_hayir("Sentetik örnek log oluşturulsun mu?"):
            yol = "ornek_erisim.log"
            if not ornek_log_olustur(yol):
                return
        else:
            return

    try:
        boyut = os.path.getsize(yol)
        if boyut > MAX_LOG_BOYUTU:
            etiket("[!]", f"Log dosyası çok büyük ({boyut / (1024 * 1024):.1f} MiB). Sınır: {MAX_LOG_BOYUTU // (1024 * 1024)} MiB.")
            return

        with open(yol, "r", encoding="utf-8", errors="replace") as dosya:
            satirlar = dosya.readlines()
    except OSError as hata:
        etiket("[!]", f"Dosya okunamadı: {hata}")
        return

    toplam_dosya_satiri = len(satirlar)
    kayitlar: list[dict[str, object]] = []
    taninamayan = 0

    for no, ham in enumerate(satirlar, start=1):
        ham_s = ham.rstrip("\n")
        if not ham_s.strip() or ham_s.lstrip().startswith("#"):
            continue
        eslesme = LOG_SATIR_DESENI.search(ham_s)
        if not eslesme:
            taninamayan += 1
            kayitlar.append({
                "no": no,
                "ham": ham_s,
                "ip": "Bilinmiyor",
                "zaman": None,
                "metod": "BİLİNMİYOR",
                "yol": ham_s,
                "kod": None,
                "tanindi": False,
            })
            continue
            
        grup = eslesme.groupdict()
        try:
            kod = int(grup["kod"])
        except (TypeError, ValueError):
            kod = None
        kayitlar.append({
            "no": no,
            "ham": ham_s,
            "ip": grup["ip"],
            "zaman": _zaman_ayikla(grup["zaman"]),
            "metod": grup["metod"],
            "yol": grup["yol"],
            "kod": kod,
            "tanindi": True,
        })

    bulgular: list[tuple[str, str, int, str]] = []
    sqli_satirlari: set[int] = set()

    # 1. SQL Injection Taraması
    for kayit in kayitlar:
        metin = str(kayit["yol"]) + " " + str(kayit["ham"])
        ip = str(kayit["ip"]) if kayit["ip"] else "-"
        no = int(kayit["no"])
        eslesen: list[str] = []
        for etiket_ad, desen in SQLI_DESENLERI:
            if re.search(desen, metin):
                eslesen.append(etiket_ad)
        if not eslesen:
            continue
        sqli_satirlari.add(no)
        aciklama = f"SQL Injection şüphe desenleri: {', '.join(eslesen)}"
        bulgular.append((ip, "SQL Injection şüphesi", no, aciklama))

    # 2. Brute-force Taraması: Mükerrer alarm üretmeyen hatasız kayan pencere mantığı
    auth_yollari_deseni = re.compile(r"(?i)(?:login|signin|auth|admin|wp-login)")
    ip_gruplari: dict[str, list[dict[str, object]]] = {}
    
    for kayit in kayitlar:
        if not kayit["tanindi"] or kayit["ip"] is None or kayit["kod"] is None:
            continue
        yol_adi = str(kayit["yol"])
        if auth_yollari_deseni.search(yol_adi) and int(kayit["kod"]) in {401, 403}:
            ip_gruplari.setdefault(str(kayit["ip"]), []).append(kayit)

    for ip, olaylar in ip_gruplari.items():
        sirali = sorted(olaylar, key=lambda x: (x["zaman"] is None, x["zaman"] or datetime.min.replace(tzinfo=timezone.utc), x["no"]))
        
        pencere: list[dict[str, object]] = []
        alarm_verildi = False

        for olay in sirali:
            zaman = olay["zaman"]
            if not isinstance(zaman, datetime):
                pencere.append(olay)
                if len(pencere) >= 4 and not alarm_verildi:
                    son_no = int(pencere[-1]["no"])
                    bulgular.append((ip, "Brute-force şüphesi", son_no, f"Zaman damgasız {len(pencere)} başarısız giriş (401/403)."))
                    alarm_verildi = True
                continue

            while pencere:
                ilk_zaman = pencere[0]["zaman"]
                if isinstance(ilk_zaman, datetime) and (zaman - ilk_zaman).total_seconds() > 60:
                    pencere.pop(0)
                    alarm_verildi = False  # Yeni zaman aralığında tekrar alarm verilebilir
                else:
                    break

            pencere.append(olay)
            if len(pencere) >= 4 and not alarm_verildi:
                son_no = int(pencere[-1]["no"])
                bulgular.append((ip, "Brute-force şüphesi", son_no, f"60 sn içinde {len(pencere)} başarısız giriş (401/403) [Yol: {pencere[0]['yol']}]"))
                alarm_verildi = True  # Bu pencere için tekrar tekrar tetiklenmesini engelle

    renkli_yaz("")
    renkli_yaz("Log Analiz Bulguları", Renkler.KALIN)
    if bulgular:
        print(f"{'IP Adresi':<18}{'Tehdit Türü':<24}{'Satır No':<10}{'Açıklama'}")
        print("-" * min(terminal_genisligi(), 96))
        for ip, tur, no, aciklama in sorted(bulgular, key=lambda x: x[2]):
            print(f"{ip:<18}{tur:<24}{no:<10}{aciklama}")
    else:
        etiket("[+]", "Belirlenen savunma kurallarına göre şüpheli bulgu yok.")
    
    etiket("[i]", f"Dosya toplam satırı : {toplam_dosya_satiri}")
    etiket("[i]", f"Analiz edilen kayıt : {len(kayitlar)} (Tanınmayan/Atlanan: {taninamayan})")
    etiket("[i]", f"Tespit edilen SQLi  : {len(sqli_satirlari)} satır")


# ---------------------------------------------------------------------------
# MODÜL 4 — Şifre ve hash
# ---------------------------------------------------------------------------

def _parola_al() -> str | None:
    if not sys.stdin.isatty():
        etiket("[!]", "Terminal TTY değil; gizli parola girişi yapılamıyor.")
        return None
    try:
        return getpass.getpass("Parola (ekranda görünmez): ")
    except (EOFError, OSError):
        return None


def _parola_puani(parola: str) -> tuple[int, str, list[str]]:
    uzunluk = len(parola)
    buyuk = any(c.isupper() for c in parola)
    kucuk = any(c.islower() for c in parola)
    rakam = any(c.isdigit() for c in parola)
    ozel = any(not c.isalnum() for c in parola)

    notlar: list[str] = []
    puan = 0

    if uzunluk < 8:
        puan += 8
        notlar.append("Uzunluk 8 karakterden kısa (Kritik zafiyet).")
    elif uzunluk < 12:
        puan += 25
        notlar.append("Uzunluk 8–11 karakter (Orta seviye).")
    else:
        puan += 45
        notlar.append("Uzunluk 12+ karakter (İyi seviye).")

    if buyuk: puan += 12; notlar.append("Büyük harf içeriyor.")
    if kucuk: puan += 12; notlar.append("Küçük harf içeriyor.")
    if rakam: puan += 13; notlar.append("Rakam içeriyor.")
    if ozel:  puan += 18; notlar.append("Özel karakter içeriyor.")

    puan = max(0, min(100, puan))
    
    if uzunluk < 8 or puan < 40:
        kat = "Zayıf"
    elif puan < 65:
        kat = "Orta"
    elif puan < 85:
        kat = "Güçlü"
    else:
        kat = "Çok Güçlü"

    return puan, kat, notlar


def sifre_hash_analiz() -> None:
    bolum_basligi("Şifre ve Hash Analizi")
    parola = _parola_al()
    if not parola:
        etiket("[!]", "Parola alınamadı.")
        return

    try:
        puan, kategori, notlar = _parola_puani(parola)
        ozet = hashlib.sha256(parola.encode("utf-8")).hexdigest()[:16]
    finally:
        parola = ""
        del parola

    renkli_yaz("")
    etiket("[+]", f"Değerlendirme: {kategori} (Skor: {puan}/100)")
    for madde in notlar:
        etiket("[i]", madde)
    etiket("[i]", f"SHA-256 Özet Önizleme (İlk 16 hane): {ozet}…")
    etiket("[i]", "Parola değişken referansı kapsam dışına çıkarıldı.")


# ---------------------------------------------------------------------------
# MODÜL 5 — DNS ve TCP Erişim Kontrolü
# ---------------------------------------------------------------------------

def ag_erisim_kontrol() -> None:
    bolum_basligi("DNS ve Host Erişim Kontrolü")
    ham = girdi_al("Hostname veya IP adresi (örn. 127.0.0.1 veya örnek.com:443): ")
    if not ham:
        return
    hedef, ozel_port = _hedef_ayikla(ham)
    if not hedef:
        etiket("[!]", "Geçerli bir hedef girilmedi.")
        return

    test_port = ozel_port if ozel_port is not None else 80

    if ip_adresi_mi(hedef):
        dns_ip = hedef
        etiket("[i]", f"Girdi doğrudan IP adresi: {hedef}")
    else:
        etiket("[~]", f"DNS çözümlemesi yapılıyor (IPv4/IPv6 uyumlu): {hedef}")
        adresler, hata = hedef_coz(hedef)
        if hata or not adresler:
            etiket("[!]", hata or "DNS çözümlenemedi.")
            return
        dns_ip = adresler[0][1]
        etiket("[+]", f"Çözümlenen IP: {dns_ip}")

    try:
        temiz_ip = dns_ip.split("%")[0]
        ip_obj = ipaddress.ip_address(temiz_ip)
        family = socket.AF_INET6 if isinstance(ip_obj, ipaddress.IPv6Address) else socket.AF_INET
        
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(TCP_ZAMAN_ASIMI)
            if family == socket.AF_INET6:
                scope_id = 0
                if "%" in dns_ip:
                    zone_name = dns_ip.split("%")[1]
                    try:
                        scope_id = socket.if_nametoindex(zone_name)
                    except (OSError, ValueError):
                        scope_id = 0
                sock.connect((temiz_ip, test_port, 0, scope_id))
            else:
                sock.connect((temiz_ip, test_port))
            etiket("[+]", f"TCP/{test_port} Portu: Erişilebilir ve açık.")
    except OSError:
        etiket("[-]", f"TCP/{test_port} Portu: Erişilemedi, kapalı veya filtreleniyor.")


# ---------------------------------------------------------------------------
# MODÜL 6 — HTTP Güvenlik Başlıkları Denetimi
# ---------------------------------------------------------------------------

def guvenlik_basliklari_analiz() -> None:
    bolum_basligi("HTTP Güvenlik Başlıkları Denetimi")
    etiket("[i]", "Web uygulamanızın savunma mekanizmalarını ve başlık yapılandırmasını test eder.")

    ham = girdi_al("Denetlenecek URL (örn. http://127.0.0.1:8080): ")
    if ham is None:
        return
    url, hata = _url_dogrula(ham)
    if hata or url is None:
        etiket("[!]", hata or "Geçersiz URL.")
        return

    etiket("[~]", f"Bağlantı kuruluyor ve başlıklar okunuyor: {url}")
    
    istek = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": "QWEROSY-SecurityHeaders-Scanner/1.7",
        },
    )

    try:
        with urllib.request.urlopen(istek, timeout=HTTP_ZAMAN_ASIMI) as yanit:
            basliklar = dict(yanit.headers)
            nihai_url = yanit.url
            if nihai_url != url:
                etiket("[i]", f"Yönlendirme takip edildi. Son URL: {nihai_url}")
    except urllib.error.HTTPError as hata:
        basliklar = dict(hata.headers)
        try:
            hata.close()
        except OSError:
            pass
    except Exception as e:
        etiket("[!]", f"Bağlantı hatası: {e}")
        return

    kritik_basliklar = {
        "Strict-Transport-Security": ("HSTS (HTTPS Zorlaması)", "MitM saldırılarını önler."),
        "Content-Security-Policy": ("CSP (İçerik Güvenlik Politikası)", "XSS ve enjeksiyonlara karşı korur."),
        "X-Frame-Options": ("Clickjacking Koruması", "İframe tabanlı tıklama hırsızlığını engeller."),
        "X-Content-Type-Options": ("MIME-Sniffing Koruması", "Dosya türü yanıltmalarını önler."),
        "Referrer-Policy": ("Referrer Politikası", "Gizli URL parametrelerinin sızmasını engeller."),
        "Permissions-Policy": ("İzin Politikası", "Donanım/tarayıcı API erişimlerini kısıtlar."),
    }

    renkli_yaz("")
    renkli_yaz("Güvenlik Başlığı Denetim Raporu", Renkler.KALIN)
    print("-" * min(terminal_genisligi(), 80))

    bulunan_sayisi = 0
    toplam_kritik = len(kritik_basliklar)
    gelen_lower = {k.lower(): v for k, v in basliklar.items()}

    for baslik_adi, (aciklama, fayda) in kritik_basliklar.items():
        if baslik_adi.lower() in gelen_lower:
            deger = gelen_lower[baslik_adi.lower()].strip()
            if deger:
                bulunan_sayisi += 1
                etiket("[+]", f"{baslik_adi}: MEVCUT")
                print(f"      Açıklama : {aciklama} ({fayda})")
                if len(deger) > 60:
                    print(f"      Değer    : {deger[:60]}...")
                else:
                    print(f"      Değer    : {deger}")
            else:
                etiket("[-]", f"{baslik_adi}: BOŞ/GEÇERSİZ")
                print(f"      Risk     : Başlık tanımlanmış ancak içeriği boş.")
        else:
            etiket("[-]", f"{baslik_adi}: EKSİK")
            print(f"      Risk     : {aciklama} tanımlanmamış. {fayda}")
        print()

    skor = int((bulunan_sayisi / toplam_kritik) * 100)
    renkli_yaz(f"Güvenlik Başlığı Skoru: %{skor}  ({bulunan_sayisi}/{toplam_kritik} başlık yapılandırılmış)", Renkler.CYAN, kalin=True)
    etiket("[i]", "Savunma Notu: Eksik başlıkların sunucu (Nginx/Apache) konfigürasyonunda eklenmesi önerilir.")


# ---------------------------------------------------------------------------
# Ana program
# ---------------------------------------------------------------------------

def main() -> int:
    renk_destegi_ayarla()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, OSError, ValueError):
        pass

    etik_uyari_goster()

    eylemler = {
        "1": port_tarayici,
        "2": dizin_bulucu,
        "3": log_analiz,
        "4": sifre_hash_analiz,
        "5": ag_erisim_kontrol,
        "6": guvenlik_basliklari_analiz,
    }

    while True:
        try:
            renkli_yaz("")
            menu_goster()
            secim = girdi_al("Seçiminiz: ", zorunlu=False)
            if secim is None:
                renkli_yaz("")
                etiket("[i]", f"{ARAC_ADI} kapatılıyor. Güvenli çalışmalar.")
                return 0
            secim = secim.strip()
            if secim == "0":
                renkli_yaz("")
                etiket("[+]", f"{ARAC_ADI} kapatıldı. Yetkili sistemlerde kalın.")
                return 0
            if secim not in eylemler:
                etiket("[!]", "Geçersiz seçim. 0–6 arasında bir değer girin.")
                continue
            try:
                eylemler[secim]()
            except KeyboardInterrupt:
                renkli_yaz("")
                etiket("[!]", "İşlem iptal edildi (Ctrl+C). Ana menüye dönülüyor.")
            except Exception as hata:
                etiket("[!]", f"Hata oluştu: {type(hata).__name__}: {hata}")
            ana_menuye_don()
        except KeyboardInterrupt:
            renkli_yaz("")
            continue


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nProgram sonlandırıldı.")
        raise SystemExit(130)