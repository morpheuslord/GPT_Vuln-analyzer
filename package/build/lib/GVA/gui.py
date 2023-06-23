import customtkinter
import openai
import nmap
import dns.resolver
from typing import Any
from subprocess import run
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

root = customtkinter.CTk()
root.title("GVA - GUI")
root.geometry("600x400")

nm = nmap.PortScanner()
model_engine = "text-davinci-003"


def application() -> None:
    try:
        apikey = entry1.get()
        openai.api_key = apikey
        target = entry2.get()
        attack = entry5.get()
        outputf = str(entry4.get())
        match attack:
            case 'geo':
                val = geoip(apikey, target)
                print(val)
                output_save(val, outputf)
            case "nmap":
                p = int(entry3.get())
                match p:
                    case 1:
                        val = scanner(target, 1)
                        print(val)
                        output_save(val, outputf)
                    case 2:
                        val = scanner(target, 2)
                        print(val)
                        output_save(val, outputf)
                    case 3:
                        val = scanner(target, 3)
                        print(val)
                        output_save(val, outputf)
                    case 4:
                        val = scanner(target, 4)
                        print(val)
                        output_save(val, outputf)
                    case 5:
                        val = scanner(target, 5)
                        print(val)
                        output_save(val, outputf)
            case "dns":
                val = dnsr(target)
                output_save(val, outputf)
            case "subd":
                val = sub(target)
                output_save(val, outputf)
    except KeyboardInterrupt:
        print("Keyboard Interrupt detected ...")


def geoip(key: str, target: str) -> Any:
    url = "https://api.ipgeolocation.io/ipgeo?apiKey={a}&ip={b}".format(
        a=key, b=target)
    content = run("curl {}".format(url))
    return content


def output_save(output: Any, outf: Any):
    top = customtkinter.CTkToplevel(root)
    top.title("GVA Output")
    top.grid_rowconfigure(0, weight=1)
    top.grid_columnconfigure(0, weight=1)
    top.textbox = customtkinter.CTkTextbox(
        master=top, height=500, width=400, corner_radius=0)
    top.textbox.grid(row=0, column=0, sticky="nsew")

    try:
        file = open(outf, 'x')
    except FileExistsError:
        file = open(outf, "r+")
    file.write(str(output))
    file.close
    top.textbox.insert("0.0", text=output)


def sub(target: str) -> Any:
    s_array = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'hod', 'butterfly', 'ckp',
               'tele2', 'receiver', 'reality', 'panopto', 't7', 'thot', 'wien', 'uat-online', 'Footer']

    ss = []
    out = ""
    for subd in s_array:
        try:
            ip_value = dns.resolver.resolve(f'{subd}.{target}', 'A')
            if ip_value:
                ss.append(f'{subd}.{target}')
                if f"{subd}.{target}" in ss:
                    print(f'{subd}.{target} | Found')
                    out += f'{subd}.{target}'
                    out += "\n"
                    out += ""
                else:
                    pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except KeyboardInterrupt:
            print('Ended')
            quit()
    return out


def dnsr(target: str) -> Any:
    analize = ''
    record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']
    for records in record_types:
        try:
            answer = dns.resolver.resolve(target, records)
            for server in answer:
                st = server.to_text()
                analize += "\n"
                analize += records
                analize += " : "
                analize += st
        except dns.resolver.NoAnswer:
            print('No record Found')
            pass
        except KeyboardInterrupt:
            print("Bye")
            quit()
    try:
        prompt = "do a DNS analysis of {} and return proper clues for an attack in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    return response


def scanner(ip: str, profile: int) -> str:
    profile_argument = ""
    # The port profiles or scan types user can choose
    if profile == 1:
        profile_argument = '-Pn -sV -T4 -O -F'
    elif profile == 2: 
        profile_argument = '-Pn -T4 -A -v'
    elif profile == 3:
        profile_argument = '-Pn -sS -sU -T4 -A -v'
    elif profile == 4:
        profile_argument = '-Pn -p- -T4 -A -v'
    elif profile == 5:
        profile_argument = '-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln'
    else:
        raise ValueError(f"Invalid Argument: {profile}")
    # The scanner with GPT Implemented
    nm.scan('{}'.format(ip), arguments='{}'.format(profile_argument))
    json_data = nm.analyse_nmap_xml_scan()
    analyze = json_data["scan"]
    try:
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analyze)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
    except KeyboardInterrupt:
        print("Bye")
        quit()
    print(response)
    return 'Done'


frame = customtkinter.CTkFrame(master=root)
frame.pack(pady=20, padx=60, fill="both", expand=True)

label = customtkinter.CTkLabel(
    master=frame, text="GVA System")
label.pack(pady=12, padx=10)

entry1 = customtkinter.CTkEntry(master=frame, placeholder_text="API_KEY")
entry1.pack(pady=12, padx=10)
entry2 = customtkinter.CTkEntry(master=frame, placeholder_text="Target")
entry2.pack(pady=12, padx=10)
entry5 = customtkinter.CTkEntry(
    master=frame, placeholder_text="Attack (nmap/dns)")
entry5.pack(pady=12, padx=10)
entry4 = customtkinter.CTkEntry(master=frame, placeholder_text="Savefile.json")
entry4.pack(pady=12, padx=10)
entry3 = customtkinter.CTkEntry(
    master=frame, placeholder_text="Profile (Only Nmap)")
entry3.pack(pady=12, padx=10)
radiobutton_var = customtkinter.IntVar(value=1)
button = customtkinter.CTkButton(
    master=frame, text="Run", command=application)
button.pack(pady=12, padx=10)

root.mainloop()
