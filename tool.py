import json
import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sys
import zipfile
import tempfile
import shutil
import psutil
import threading
import os
# Don Kilot tarafından yapılmış
class GameClient:
    def __init__(self):
        # Varsayılan ayarları en başta tanımla
        self.default_settings = {
            "game_path": r"C:\Program Files (x86)\Steam\steamapps\common\Limbus Company",
            "language": "Türkçe"
        }
        
        # Tek instance kontrolü
        self.check_single_instance()
        
        # Kullanıcı giriş kontrolü
        if not self.check_login():
            sys.exit(0)
        
        # Config dosyası yolu
        self.config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "limbus_client_config.json")
        
        # Ayarları yükle
        self.settings = self.default_settings.copy()
        self.load_config()
        
        # UI oluştur
        self.root = tk.Tk()
        self.root.withdraw()  # Ana pencereyi başlangıçta gizle
        self.create_ui()
        
        # Oyun yolunu doğrula
        self.root.after(100, self.verify_game_path)
        self.root.deiconify()  # UI hazır olduğunda göster
        self.root.mainloop()
    
    def check_single_instance(self):
        """Uygulamanın zaten çalışıp çalışmadığını kontrol eder"""
        current_pid = os.getpid()
        current_name = os.path.basename(sys.argv[0])
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if (proc.info['name'] == current_name and 
                    proc.info['pid'] != current_pid):
                    proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def check_login(self):
        """Kullanıcı giriş kontrolü yapar"""
        # Hatırlama dosyası yolu
        remember_file = os.path.join(self.default_settings["game_path"], "LimbusCompany_Data", "hatirla")
        
        # Eğer hatırlama dosyası varsa ve doğruysa giriş yapmadan devam et
        if os.path.exists(remember_file):
            try:
                with open(remember_file, "r", encoding="utf-8") as f:
                    credentials = json.load(f)
                
                if self.validate_credentials(credentials["username"], credentials["password"]):
                    return True
            except:
                pass
        
        # Giriş penceresini göster
        return self.show_login_window()
    
    def show_login_window(self):
        """Giriş penceresini oluşturur"""
        self.login_root = tk.Tk()
        self.login_root.title("Limbus Company - Kullanıcı Girişi")
        self.login_root.geometry("500x350")
        self.login_root.resizable(False, False)
        self.login_root.configure(bg="#36393e")  # Daha koyu arka plan
        
        # Stil ayarları
        style = ttk.Style()
        style.theme_use('clam')
        
        # Frame stilleri
        style.configure('TFrame', background='#36393e')
        style.configure('TLabelframe', background='#36393e', bordercolor='#424549')
        style.configure('TLabelframe.Label', background='#36393e', foreground='white')
        
        # Entry (metin kutusu) stilini ayarla
        style.configure('TEntry', 
                      fieldbackground='#424549',
                      foreground='white',
                      insertcolor='white',
                      bordercolor='#424549',
                      lightcolor='#424549',
                      darkcolor='#424549',
                      padding=5)
        
        # Label stilleri
        style.configure('TLabel', background='#36393e', foreground='white')
        
        # Checkbutton stilleri
        style.configure('TCheckbutton', background='#36393e', foreground='white')
        style.map('TCheckbutton',
                background=[('active', '#36393e')])
        
        # Button stilleri
        style.configure("Login.TButton", foreground="white", background="#b01c37", font=("Arial", 10, "bold"))
        style.map("Login.TButton",
                background=[("active", "#81162a")])
        
        # Başlık
        title_frame = ttk.Frame(self.login_root)
        title_frame.pack(fill="x", pady=(15, 20), padx=20)
        
        title_label = ttk.Label(title_frame, 
                 text="Limbus Company Yama İndirici",
                 font=("Arial", 12, "bold"))
        title_label.pack()
        
        # Ana içerik çerçevesi
        main_frame = ttk.Frame(self.login_root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Kullanıcı adı
        username_frame = ttk.LabelFrame(main_frame, text=" Kullanıcı Adı ", padding=10)
        username_frame.pack(fill="x", pady=(0, 10))
        
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(username_frame, textvariable=self.username_var, width=25)
        username_entry.pack(fill="x")
        
        # Şifre
        password_frame = ttk.LabelFrame(main_frame, text=" Şifre ", padding=10)
        password_frame.pack(fill="x", pady=(0, 10))
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*", width=25)
        password_entry.pack(fill="x")
        
        # Şifreyi göster/gizle ve hatırla
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill="x", pady=(5, 0))
        
        self.show_password_var = tk.BooleanVar(value=False)
        show_pass_btn = ttk.Checkbutton(options_frame, 
                                       text="Şifreyi Göster", 
                                       variable=self.show_password_var,
                                       command=lambda: self.toggle_password_visibility(password_entry))
        show_pass_btn.pack(side="left", padx=(0, 10))
        
        self.remember_var = tk.BooleanVar(value=False)
        remember_btn = ttk.Checkbutton(options_frame, text="Beni Hatırla", variable=self.remember_var)
        remember_btn.pack(side="left")
        
        # Giriş butonu
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(15, 0))
        
        login_btn = ttk.Button(button_frame,
                  text="Giriş Yap",
                  command=self.attempt_login,
                  style="Login.TButton")
        login_btn.pack(fill="x")
        
        # Durum mesajı
        self.login_status = tk.StringVar()
        status_label = ttk.Label(main_frame, 
                                textvariable=self.login_status,
                                font=("Arial", 9),
                                foreground="#ff6b6b")
        status_label.pack(pady=(10, 0))
        
        # Enter tuşu ile giriş
        password_entry.bind('<Return>', lambda event: self.attempt_login())
        
        self.login_success = False
        self.login_root.protocol("WM_DELETE_WINDOW", lambda: sys.exit(0))
        self.login_root.mainloop()
        return self.login_success
    
    def toggle_password_visibility(self, entry):
        """Şifre görünürlüğünü değiştirir"""
        if self.show_password_var.get():
            entry.config(show="")
        else:
            entry.config(show="*")
    
    def attempt_login(self):
        """Giriş denemesi yapar"""
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not username or not password:
            self.login_status.set("Kullanıcı adı ve şifre gerekli!")
            return
        
        # Doğrulama işlemini thread'de yap
        threading.Thread(target=self.validate_login, args=(username, password), daemon=True).start()
    
    def validate_login(self, username, password):
        """Giriş bilgilerini doğrular (thread'de çalışır)"""
        self.login_root.after(0, lambda: self.login_status.set("Doğrulanıyor..."))
        
        if self.validate_credentials(username, password):
            # Hatırlama seçeneği işaretliyse kaydet
            if self.remember_var.get():
                self.save_credentials(username, password)
            
            self.login_success = True
            self.login_root.after(0, self.login_root.destroy)
        else:
            self.login_root.after(0, lambda: self.login_status.set("Geçersiz kullanıcı adı veya şifre!"))
    
    def validate_credentials(self, username, password):
        """GitHub'dan kullanıcı bilgilerini doğrular"""
        try:
            response = requests.get("https://raw.githubusercontent.com/DonKilot/Limbus-Admin-Aleti/main/important.txt")
            if response.status_code != 200:
                return False
            
            # GitHub'dan gelen içeriği ayrıştır
            content = response.text
            valid_username = None
            valid_password = None
            
            for line in content.splitlines():
                if line.startswith("Kullanıcı:"):
                    valid_username = line.split(":")[1].strip()
                elif line.startswith("Password:"):
                    valid_password = line.split(":")[1].strip()
            
            # Bilgileri karşılaştır
            return username == valid_username and password == valid_password
        except:
            return False
    
    def save_credentials(self, username, password):
        """Kullanıcı bilgilerini kaydeder"""
        remember_file = os.path.join(self.default_settings["game_path"], "LimbusCompany_Data", "hatirla")
        
        try:
            # Dizin yoksa oluştur
            os.makedirs(os.path.dirname(remember_file), exist_ok=True)
            
            # Bilgileri kaydet
            with open(remember_file, "w", encoding="utf-8") as f:
                json.dump({"username": username, "password": password}, f)
        except:
            pass
    
    def create_ui(self):
        """Kullanıcı arayüzünü oluşturur"""
        self.root.title("Limbus Company Türkçe Yama Clientı")
        self.root.geometry("600x400")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.configure(bg="#36393e")  # Ana pencere arka plan rengi
        
        # Stil ayarları
        style = ttk.Style()
        style.theme_use('clam')
        
        # Frame stilleri
        style.configure('TFrame', background='#36393e')
        style.configure('Header.TFrame', background='#2c2f33')
        style.configure('Main.TFrame', background='#36393e')
        style.configure('Footer.TFrame', background='#2c2f33')
        
        # Entry (metin kutusu) stilini ayarla
        style.configure('TEntry', 
                      fieldbackground='#424549',
                      foreground='white',
                      insertcolor='white',
                      bordercolor='#424549',
                      lightcolor='#424549',
                      darkcolor='#424549',
                      padding=5)
        
        # Label stilleri
        style.configure('TLabel', background='#36393e', foreground='white')
        
        # Button stilleri
        style.configure("Accent.TButton", foreground="white", background="#b01c37", font=("Arial", 10, "bold"))
        style.configure("Secondary.TButton", foreground="white", background="#4f545c", font=("Arial", 10))
        style.map("Accent.TButton",
                background=[("active", "#81162a")])
        style.map("Secondary.TButton",
                background=[("active", "#3c4149")])
        
        # Progressbar stili
        style.configure("Horizontal.TProgressbar", 
                      background='#b01c37',
                      troughcolor='#424549',
                      bordercolor='#424549',
                      lightcolor='#b01c37',
                      darkcolor='#b01c37')
        
        # Başlık çerçevesi
        header_frame = ttk.Frame(self.root, style="Header.TFrame")
        header_frame.pack(fill="x", pady=(0, 20))
        
        # Başlık
        title_label = ttk.Label(header_frame, 
                 text="Limbus Company Türkçe Yama İndirici",
                 font=("Arial", 16, "bold"),
                 foreground="white")
        title_label.pack(pady=15)
        
        # Ana frame
        main_frame = ttk.Frame(self.root, padding=20, style="Main.TFrame")
        main_frame.pack(expand=True, fill="both", padx=20, pady=(0, 20))
        
        # Durum bilgisi
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill="x", pady=(0, 15))
        
        self.status_var = tk.StringVar(value="Hazır")
        status_label = ttk.Label(status_frame, 
                 textvariable=self.status_var,
                 font=("Arial", 10))
        status_label.pack(side="left")
        
        # İlerleme çubuğu
        self.progress = ttk.Progressbar(main_frame, orient="horizontal", length=400, mode="determinate", style="Horizontal.TProgressbar")
        self.progress.pack(pady=10, fill="x")
        
        # Butonlar
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill="x", pady=20)
        
        # İndirme butonu
        download_btn = ttk.Button(buttons_frame,
                  text="Yamayı İndir ve Kur",
                  command=self.start_download_thread,
                  style="Accent.TButton",
                  width=20)
        download_btn.pack(pady=10, fill="x")
        
        # Ayarlar butonu
        settings_btn = ttk.Button(buttons_frame,
                  text="Ayarlar",
                  command=self.show_settings,
                  style="Secondary.TButton",
                  width=20)
        settings_btn.pack(pady=5, fill="x")
        
        # Çıkış butonu
        exit_btn = ttk.Button(buttons_frame,
                  text="Çıkış",
                  command=self.on_close,
                  style="Secondary.TButton",
                  width=20)
        exit_btn.pack(pady=5, fill="x")
        
        # Lisans bilgisi
        footer_frame = ttk.Frame(self.root, style="Footer.TFrame")
        footer_frame.pack(side="bottom", fill="x")
        
        license_label = ttk.Label(footer_frame, 
                 text="© 2023 Don Kilot - Tüm hakları saklıdır",
                 font=("Arial", 8),
                 foreground="#99aab5")
        license_label.pack(pady=5)
    
    def start_download_thread(self):
        """İndirme işlemini thread'de başlatır"""
        threading.Thread(target=self.download_and_install, daemon=True).start()
    
    def download_and_install(self):
        """GitHub'dan dosyaları indirir ve kurar"""
        temp_dir = None
        try:
            self.status_var.set("İndirme başlıyor...")
            self.progress["value"] = 0
            self.root.update()
            
            # Geçici dosya oluştur
            temp_dir = tempfile.mkdtemp()
            temp_zip = os.path.join(temp_dir, "update.zip")
            
            # İndirme işlemi
            self.status_var.set("GitHub'dan indiriliyor...")
            response = requests.get("https://github.com/Pepsiman9000/limbuscompanyturkishtranslation/archive/main.zip", stream=True)
            
            if response.status_code != 200:
                raise Exception(f"GitHub bağlantı hatası: {response.status_code}")
            
            total_size = int(response.headers.get('content-length', 1))  # Sıfır bölme hatasını önlemek için 1
            downloaded = 0
            chunk_size = 8192
            
            with open(temp_zip, 'wb') as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        # Sıfır bölme hatasını önle
                        progress = min((downloaded / max(total_size, 1)) * 50, 50)
                        self.progress["value"] = progress
                        self.root.update()
            
            # ZIP'i açma
            self.status_var.set("Dosyalar çıkarılıyor...")
            self.progress["value"] = 50
            self.root.update()
            
            with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Hedef yapıyı oluştur
            lang_dir = os.path.join(self.settings["game_path"], "LimbusCompany_Data", "Lang")
            turkish_dir = os.path.join(lang_dir, "Turkish")
            
            # Eski dosyaları temizle
            self.status_var.set("Eski dosyalar temizleniyor...")
            self.progress["value"] = 60
            self.root.update()
            shutil.rmtree(turkish_dir, ignore_errors=True)
            os.makedirs(turkish_dir, exist_ok=True)
            
            # config.json oluştur
            config_path = os.path.join(lang_dir, "config.json")
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump({"lang": "Turkish"}, f, indent=4, ensure_ascii=False)
            
            # Tüm dosyaları kopyala (Additional Files hariç)
            extracted_root = os.path.join(temp_dir, "limbuscompanyturkishtranslation-main")
            
            # 1. Ana dizindeki tüm dosya ve klasörleri kopyala (Additional Files hariç)
            self.status_var.set("Dosyalar kopyalanıyor...")
            self.progress["value"] = 70
            self.root.update()
            
            items = [item for item in os.listdir(extracted_root) if item != "Additional Files"]
            total_items = max(len(items), 1)  # Sıfır bölme hatasını önle
            
            for i, item in enumerate(items):  
                src = os.path.join(extracted_root, item)
                dst = os.path.join(turkish_dir, item)
                
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(src, dst)
                
                # İlerleme güncelleme
                progress = 70 + (i / total_items) * 15
                self.progress["value"] = min(progress, 85)  # Sınırlama
                self.root.update()
            
            # 2. Additional Files klasörünü kopyala
            additional_files_dir = os.path.join(extracted_root, "Additional Files")
            if os.path.exists(additional_files_dir):
                items = os.listdir(additional_files_dir)
                total_items = max(len(items), 1)  # Sıfır bölme hatasını önle
                
                for i, item in enumerate(items):
                    src = os.path.join(additional_files_dir, item)
                    dst = os.path.join(turkish_dir, item)
                    
                    if os.path.isdir(src):
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src, dst)
                    
                    # İlerleme güncelleme
                    progress = 85 + (i / total_items) * 15
                    self.progress["value"] = min(progress, 100)  # Sınırlama
                    self.root.update()
            else:
                self.progress["value"] = 100
                self.root.update()
            
            # Temizlik
            self.status_var.set("Temizlik yapılıyor...")
            self.root.update()
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            self.status_var.set("Yama başarıyla kuruldu!")
            messagebox.showinfo("Başarılı", "Türkçe yama başarıyla indirildi ve kuruldu!")
            
        except Exception as e:
            self.status_var.set("Hata oluştu!")
            messagebox.showerror("Hata", f"İşlem sırasında hata oluştu:\n{str(e)}")
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
        finally:
            # İşlem bitince ilerlemeyi sıfırla
            self.root.after(3000, lambda: self.progress.config(value=0))

    def verify_game_path(self):
        """Oyun path'ini kontrol eder, yoksa kullanıcıdan seçmesini ister"""
        game_exe = os.path.join(self.settings["game_path"], "LimbusCompany.exe")
        game_data = os.path.join(self.settings["game_path"], "LimbusCompany_Data")
        
        if not (os.path.isfile(game_exe) and os.path.isdir(game_data)):
            messagebox.showwarning(
                "Path Bulunamadı", 
                f"Oyun path'i bulunamadı:\n{self.settings['game_path']}\n\nLütfen doğru path'i seçin."
            )
            self.choose_game_path()
    
    def choose_game_path(self):
        """Kullanıcıdan oyun path'i seçmesini ister"""
        new_path = filedialog.askdirectory(
            title="Limbus Company Kurulum Dizini Seçin",
            initialdir=r"C:\Program Files (x86)\Steam\steamapps\common"
        )
        
        if new_path:
            # Path doğrulama
            game_exe = os.path.join(new_path, "LimbusCompany.exe")
            game_data = os.path.join(new_path, "LimbusCompany_Data")
            
            if os.path.isfile(game_exe) and os.path.isdir(game_data):
                self.settings["game_path"] = new_path
                self.save_config()
                return True
            else:
                messagebox.showwarning(
                    "Geçersiz Path",
                    "Seçtiğiniz dizin geçerli bir Limbus Company kurulumu değil!"
                )
                return self.choose_game_path()
        return False
    
    def load_config(self):
        """Config dosyasını yükler veya oluşturur"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    loaded_settings = json.load(f)
                    # Sadece geçerli anahtarları güncelle
                    for key in self.default_settings:
                        if key in loaded_settings:
                            self.settings[key] = loaded_settings[key]
        except Exception as e:
            messagebox.showwarning(
                "Config Hatası",
                f"Config dosyası okunamadı, varsayılan ayarlar kullanılacak:\n{str(e)}"
            )
    
    def save_config(self):
        """Ayarları config dosyasına kaydeder"""
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=4, ensure_ascii=False)
        except Exception as e:
            messagebox.showerror(
                "Kayıt Hatası",
                f"Config dosyası kaydedilemedi:\n{str(e)}"
            )
    
    def show_settings(self):
        """Ayarlar penceresini gösterir"""
        settings_win = tk.Toplevel(self.root)
        settings_win.title("Ayarlar")
        settings_win.geometry("500x200")
        settings_win.grab_set()  # Modal pencere
        settings_win.configure(bg="#36393e")
        
        # Ana frame
        main_frame = ttk.Frame(settings_win, padding=20)
        main_frame.pack(expand=True, fill="both")
        
        # Path ayarı
        path_frame = ttk.LabelFrame(main_frame, text=" Oyun Kurulum Path'i ", padding=10)
        path_frame.pack(fill="x", pady=(0, 15))
        
        self.path_var = tk.StringVar(value=self.settings["game_path"])
        entry_frame = ttk.Frame(path_frame)
        entry_frame.pack(fill="x")
        
        ttk.Entry(entry_frame, textvariable=self.path_var, style='TEntry').pack(side="left", expand=True, fill="x")
        ttk.Button(entry_frame, text="Gözat...", command=self.browse_path).pack(side="left", padx=5)
        
        # Kaydet butonu
        ttk.Button(main_frame, 
                  text="Ayarları Kaydet", 
                  command=lambda: self.save_settings(settings_win),
                  style="Accent.TButton").pack(fill="x")
    
    def browse_path(self):
        """Path seçme dialogunu açar"""
        if self.choose_game_path():
            self.path_var.set(self.settings["game_path"])
    
    def save_settings(self, settings_win):
        """Ayarları kaydeder"""
        self.settings["game_path"] = self.path_var.get()
        self.save_config()
        messagebox.showinfo("Başarılı", "Ayarlar başarıyla kaydedildi!")
        settings_win.destroy()
    
    def on_close(self):
        """Pencere kapatıldığında temizlik yapar"""
        self.root.destroy()
        sys.exit(0)

if __name__ == "__main__":
    try:
        # Yönetici izni kontrolü (Windows için)
        if os.name == 'nt' and not os.access(r"C:\Program Files (x86)", os.W_OK):
            import ctypes
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
            sys.exit(0)
            
        GameClient()
    except Exception as e:
        messagebox.showerror("Başlatma Hatası", f"Client başlatılamadı:\n{str(e)}")
        sys.exit(1)
