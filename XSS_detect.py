import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urlencode, urljoin
import re
import os

def parse_form(url, cookie):
    form_list=[]
    page_content = requests.get(url,cookies=cookie).content
    soup = bs(page_content, "html.parser")
    for form in soup.find_all("form"):
        details = {}
        action = form.attrs.get("action") # form의 이동할 action url
        method = form.attrs.get("method", "get").lower() # form method (GET, POST, etc...)
        inputs = [] # get all the input details such as type and name
        for select_tag in form.find_all("select"):
            select_name = select_tag.attrs.get("name")
            inputs.append({"type": "select", "name": select_name, "value":" "})
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            if input_type == "submit" or input_tag.get('value'):
                inputs.append({"type": input_type, "name": input_name, "value": input_tag.attrs.get("value")})
            else : inputs.append({"type": input_type, "name": input_name, "value":" "})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        if len(details["inputs"]) > 0:
            form_list.append(details)
    return form_list


def reflected_scan_xss(form_details, url, payload, cookies, gui):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    report_xss_reflected = []
    data = {}
    
    for input in inputs:
       data[input["name"]] = input["value"]
    data_key = list(data.keys())
    temp = data.copy()      
    if form_details["method"] == "post":
        for pl_key in data_key:
            reflect_data = data.copy()
            for reflect_pl in payload:
                reflect_data[pl_key] = temp[pl_key]+reflect_pl
                res_p = requests.post(target_url, cookies=cookies, data=reflect_data).content.decode()
                if reflect_pl in res_p:
                    gui.output_str.emit(f" [취약점 식별(Reflected XSS)] {str(reflect_data)}")
                    report_xss_reflected.append(str(reflect_data))
                    
    elif form_details["method"] == "get":
        for pl_key in data_key:
            reflect_data = data.copy()
            for reflect_pl in payload:
                reflect_data[pl_key] = temp[pl_key]+reflect_pl
                res_g = requests.get(target_url, cookies=cookies, params=reflect_data).content.decode()
                if reflect_pl in res_g:
                    gui.output_str.emit(f" [취약점 식별(Reflected XSS)] {str(reflect_data)}")
                    report_xss_reflected.append(str(reflect_data))
    return report_xss_reflected
                    
def dom_scan_xss(url, cookies, gui):
    response = requests.post(url, cookies = cookies, verify=False).content.decode()
    highlighted = []
    sources = r'''document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage'''
    sinks = r'''eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript|crypto.generateCRMFRequest|ScriptElement\.(src|text|textContent|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(document|window)\.location'''
    scripts = re.findall(r'(?i)(?s)<script[^>]*>(.*?)</script>', response)
    sinkFound, sourceFound = False, False
    for script in scripts:
        script = script.split('\n')
        try:
            for newLine in script:
                line = newLine
                parts = line.split('var ')
                pattern = re.finditer(sources, newLine)
                for grp in pattern:
                    if grp:
                        source = newLine[grp.start():grp.end()].replace(' ', '')
                        if source:
                            if len(parts) > 1:
                               for part in parts:
                                    if source in part:
                                        sourceFound = True
                            line = line.replace(source,  source)
                pattern = re.finditer(sinks, newLine)
                for grp in pattern:
                    if grp:
                        sink = newLine[grp.start():grp.end()].replace(' ', '')
                        if sink:
                            line = line.replace(sink, sink+ ' ')
                            sinkFound = True
                if line != newLine:
                    gui.output_str.emit(' [취약점 식별(DOM XSS)] : %s' % (line.lstrip(' \t')))
                    highlighted.append('%s' % (line.lstrip(' \t')))
        except MemoryError:
            pass
    if sinkFound and sourceFound:
        return highlighted
    else:
        return []

if __name__ == "__main__":
    # target_url = "https://bwapp.hakhub.net/xss_get.php"
    target_url = "http://localhost/DVWA/vulnerabilities/xss_r/"
    # target_url = "https://shop.hakhub.net/"
    target_url_dom = "http://127.0.0.1/dvwa/vulnerabilities/xss_d/"
    input_cookies = {
        "PHPSESSID" : "srfq8nl4ue6fpvm837hctm7pe4",
        "security_level" : "0"
    }
    
    dom_input_cookies = {
        "PHPSESSID" : "o5f2def7678ls5ot7o3c8us8hf",
        "security" : "low"
    }
    with open(os.path.dirname(os.path.realpath(__file__))+'/payloads/xss_payloads_list.txt', "r", encoding="utf-8") as vector_file:
        payloads = vector_file.read().split('\n')

    form_list = parse_form(target_url, dom_input_cookies)
    for form in form_list : 
        if form["action"] == "None":
            pass
        else:
            reflected_scan_xss(form, target_url, payloads, dom_input_cookies)

    dom_detect = dom_scan_xss(target_url_dom, cookies = dom_input_cookies)