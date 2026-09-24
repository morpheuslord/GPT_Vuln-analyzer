import tkinter as tk
import json
from dotenv import load_dotenv
import customtkinter
import os
from components.ai_providers import AIEngine, AnalysisReport, PROVIDER_CLASSES, config_from_keys, normalize_selection
from components.dns_recon import DNSRecon
from components.geo import geo_ip_recon
from components.port_scanner import NetworkScanner
from components.jwt import JWTAnalyzer
from components.packet_analysis import PacketAnalysis
from components.subdomain import SubEnum

list_loc = "lists//default.txt"
load_dotenv()
gkey = os.getenv('GEOIP_API_KEY')

dns_enum = DNSRecon()
geo_ip = geo_ip_recon()
packet_analysis = PacketAnalysis()
port_scanner = NetworkScanner()
jwt_analyzer = JWTAnalyzer()
sub_recon = SubEnum()
engine = AIEngine(config_from_keys(
    openai_key=os.getenv('OPENAI_API_KEY'),
    anthropic_key=os.getenv('ANTHROPIC_API_KEY'),
    gemini_key=os.getenv('GEMINI_API_KEY') or os.getenv('BARD_API_KEY'),
    runpod_key=os.getenv('RUNPOD_API_KEY'),
    runpod_endpoint=os.getenv('RUNPOD_ENDPOINT_ID'),
))
AI_PROVIDER_CHOICES = [*PROVIDER_CLASSES, "all"]

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

root = customtkinter.CTk()
root.title("GVA - GUI")
root.geometry("800x400")

paned_window = tk.PanedWindow(root, orient="horizontal")
paned_window.pack(fill="both", expand=True)
input_frame = customtkinter.CTkFrame(paned_window, width=400)
output_frame = customtkinter.CTkFrame(paned_window, width=400)
paned_window.add(input_frame)
paned_window.add(output_frame)
navigation_frame = customtkinter.CTkFrame(input_frame, width=100)
navigation_frame.pack(side="left", fill="y")


def application(attack, entry2, entry3, entry_ai, entry5=None):
    try:
        target = entry2.get()
        profile = entry3.get() if entry3 else None
        save_loc = entry5.get() if entry5 else None
        ai_choices = entry_ai.get() if entry_ai else None

        providers = normalize_selection(ai_choices) if ai_choices else ['openai']

        if attack == 'geo':
            geo_output: str = geo_ip.geoip(gkey, target)
            output_save(str(geo_output))
        elif attack == 'nmap':
            p1_out = port_scanner.scanner(
                target, int(profile) if profile else 1, engine, providers)
            output_save(p1_out)
        elif attack == 'dns':
            dns_output = dns_enum.dns_resolver(target, engine, providers)
            output_save(dns_output)
        elif attack == 'sub':
            sub_output: str = sub_recon.sub_enumerator(target, list_loc)
            output_save(sub_output)
        elif attack == 'jwt':
            output = jwt_analyzer.analyze(target, engine, providers)
            output_save(output)
        elif attack == 'pcap':
            packet_analysis.perform_full_analysis(
                pcap_path=target,
                json_path=save_loc,
            )
            output_save("Done")
    except KeyboardInterrupt:
        print("Keyboard Interrupt detected ...")


def output_save(output) -> None:
    output_textbox.delete("1.0", "end")
    if output == "Done":
        output_textbox.insert("1.0", "Status: Successful")
        return
    if isinstance(output, AnalysisReport):
        # Show the consolidated (deliberated) report, or the single result.
        display = {}
        if output.errors:
            display["errors"] = output.errors
        if output.consolidated is not None:
            display["consolidated"] = output.consolidated
            display["individual"] = output.individual
        elif output.individual:
            display.update(output.individual)
        output_textbox.insert("1.0", json.dumps(display, indent=2))
        return
    try:
        output_textbox.insert("1.0", json.dumps(json.loads(output), indent=2))
    except (json.JSONDecodeError, TypeError):
        output_textbox.insert("1.0", str(output))


def select_frame_by_name(name):
    global frame
    frame.destroy()
    frame = customtkinter.CTkFrame(master=input_frame)
    frame.pack(pady=20, padx=20, fill="both", expand=True)

    label_text = f"GVA System - {name.capitalize()}"
    label = customtkinter.CTkLabel(master=frame, text=label_text)
    label.pack(pady=12, padx=10)

    entry2 = customtkinter.CTkEntry(master=frame, placeholder_text="Target/capfile/token")
    entry2.pack(pady=12, padx=10)

    if name in ["nmap", "dns", "jwt"]:
        entry_ai = customtkinter.CTkComboBox(master=frame, values=AI_PROVIDER_CHOICES, state="readonly")
        entry_ai.set("Select AI Input")
        entry_ai.pack(pady=12, padx=10)
    else:
        entry_ai = None

    entry3 = None
    entry5 = None
    if name == "nmap":
        entry3 = customtkinter.CTkEntry(master=frame, placeholder_text="Profile")
        entry3.pack(pady=12, padx=10)
    elif name == "sub":
        entry3 = customtkinter.CTkEntry(master=frame, placeholder_text="File Location")
        entry3.pack(pady=12, padx=10)
    elif name == "pcap":
        entry5 = customtkinter.CTkEntry(master=frame, placeholder_text="Save Location")
        entry5.pack(pady=12, padx=10)

    button = customtkinter.CTkButton(master=frame, text="Run", command=lambda: application(
        attack=name,
        entry2=entry2,
        entry3=entry3,
        entry_ai=entry_ai,
        entry5=entry5
    ))
    button.pack(pady=12, padx=10)


nmap_button = customtkinter.CTkButton(navigation_frame, text="Nmap", command=lambda: select_frame_by_name("nmap"))
nmap_button.pack(side="top", pady=5, anchor="center")
dns_button = customtkinter.CTkButton(navigation_frame, text="DNS", command=lambda: select_frame_by_name("dns"))
dns_button.pack(side="top", pady=5, anchor="center")
sub_button = customtkinter.CTkButton(navigation_frame, text="Subdomain", command=lambda: select_frame_by_name("sub"))
sub_button.pack(side="top", pady=5, anchor="center")
jwt_button = customtkinter.CTkButton(navigation_frame, text="JWT Analysis", command=lambda: select_frame_by_name("jwt"))
jwt_button.pack(side="top", pady=5, anchor="center")
pcap_button = customtkinter.CTkButton(navigation_frame, text="Pcap Analysis", command=lambda: select_frame_by_name("pcap"))
pcap_button.pack(side="top", pady=5, anchor="center")
geo_button = customtkinter.CTkButton(navigation_frame, text="GeoIP Recon", command=lambda: select_frame_by_name("geo"))
geo_button.pack(side="top", pady=5, anchor="center")

frame = customtkinter.CTkFrame(master=input_frame)
frame.pack(pady=20, padx=20, fill="both", expand=True)
label = customtkinter.CTkLabel(master=frame, text="GVA System")
label.pack(pady=12, padx=10)
entry2 = customtkinter.CTkEntry(master=frame, placeholder_text="Target")
entry2.pack(pady=12, padx=10)
entry_ai = customtkinter.CTkComboBox(master=frame, values=AI_PROVIDER_CHOICES, state="readonly")
entry_ai.set("Select AI Input")
entry_ai.pack(pady=12, padx=10)
entry3 = customtkinter.CTkEntry(master=frame, placeholder_text="Profile (Only Nmap)")
entry3.pack(pady=12, padx=10)
button = customtkinter.CTkButton(master=frame, text="Run", command=lambda: application("default", entry2, entry3, entry_ai))
button.pack(pady=12, padx=10)
output_textbox = customtkinter.CTkTextbox(master=output_frame, height=800, width=900, corner_radius=0)
output_textbox.pack(pady=12, padx=10)

root.mainloop()
