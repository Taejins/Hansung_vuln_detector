import requests
from bs4 import BeautifulSoup as bs
from colorama import init, Fore  # pip install colorama
from urllib.parse import urljoin, urlencode
import re
from pprint import pprint


def parse_form(url, cookie):
    form_list = []
    page_content = requests.get(url, cookies=cookie).content
    soup = bs(page_content, "html.parser")
    for form in soup.find_all("form"):
        details = {}
        action = form.attrs.get("action")  # form의 이동할 action url
        # form method (GET, POST, etc...)
        method = form.attrs.get("method", "get").lower()
        inputs = []  # get all the input details such as type and name
        for select_tag in form.find_all("select"):
            select_name = select_tag.attrs.get("name")
            inputs.append(
                {"type": "select", "name": select_name, "value": " "})
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            if input_type == "submit" or input_tag.get('value'):
                inputs.append({"type": input_type, "name": input_name,
                              "value": input_tag.attrs.get("value")})
            else:
                inputs.append(
                    {"type": input_type, "name": input_name, "value": " "})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        if len(details["inputs"]) > 0:
            form_list.append(details)
    return form_list


def sqli_url_scan(url, cookie, payload, err, gui):
    report_sqli_url = []
    for pl in payload:
        scan_url = f"{url}{pl}"
        response = requests.get(url, cookies=cookie)
        if check_sqli_vuln(response.text, err):
            gui.output_str.emit(f" [취약점 식별(URL 기반)]\t{scan_url}")
            report_sqli_url.append(scan_url)
    return report_sqli_url


def sqli_form_scan(url, cookie, payload, bool, err, forms, gui):
    report_sqli_error = []
    report_sqli_boolean = []
    target_url = urljoin(url, forms["action"])
    joined_url = ""
    inputs = forms["inputs"]
    data = {}

    for input in inputs:
        data[input["name"]] = input["value"]
        try:
            data_key = list(data.keys())
            temp = data.copy()
            if forms["method"] == "get":
                for pl_key in data_key:
                    # error based sqli
                    error_data = data.copy()
                    for error_pl in payload:
                        error_data[pl_key] = temp[pl_key]+error_pl
                        joined_url = target_url + "?" + urlencode(error_data)
                        response = requests.get(
                            joined_url, params=error_data, cookies=cookie).content.decode()
                        if check_sqli_vuln(response, err):
                            gui.output_str.emit(f"  [취약점 식별(에러 기반)] {joined_url}")
                            report_sqli_error.append(joined_url)
                    #boolean based sqli
                    bool_data = data.copy()
                    for bool_pl in bool:
                        true_pl, false_pl = bool_pl.split("\t")
                        bool_data[pl_key] = temp[pl_key]+true_pl
                        joined_url1 = target_url + "?" + urlencode(bool_data)
                        t_res = requests.get(
                            joined_url1, params=bool_data, cookies=cookie).content.decode()
                        bool_data[pl_key] = temp[pl_key]+false_pl
                        joined_url2 = target_url + "?" + urlencode(bool_data)
                        f_res = requests.get(
                            joined_url2, params=bool_data, cookies=cookie).content.decode()
                        if len(t_res) != len(f_res):
                            gui.output_str.emit(f"  [취약점 식별(Bool 기반)] {joined_url1}\n                                  {joined_url2}")
                            report_sqli_boolean.append(f"{joined_url1}\n          {joined_url2}")

            elif forms["method"] == "post":
                for pl_key in data_key:
                    # error based sqli
                    error_data = data.copy()
                    for error_pl in payload:
                        error_data[pl_key] = temp[pl_key]+error_pl
                        response = requests.post(
                            target_url, data=error_data, cookies=cookie).content.decode()
                        if check_sqli_vuln(response, err):
                            gui.output_str.emit(f"  [취약점 식별(에러 기반)] {target_url}  {str(error_data)}")
                            report_sqli_error.append(f"{{'{pl_key}':'{error_pl}'}}")
                    #boolean based sqli
                    bool_data = data.copy()
                    for bool_pl in bool:
                        true_pl, false_pl = bool_pl.split("\t")
                        bool_data[pl_key] = temp[pl_key]+true_pl
                        t_res = requests.get(
                            target_url, data=bool_data, cookies=cookie)
                        bool_data[pl_key] = temp[pl_key]+false_pl
                        f_res = requests.get(
                            target_url, data=bool_data, cookies=cookie)
                        if len(str(bs(t_res.text, "html.parser"))) != len(str(bs(t_res.text, "html.parser"))):
                            gui.output_str.emit(f"  [취약점 식별(Bool 기반)]\t{target_url}\n  {{'{pl_key}': True[{true_pl}], False[{false_pl}]}}")
                            report_sqli_boolean.append(f"{{'{pl_key}': True[{true_pl}], False[{false_pl}]}}")
        except Exception as e:
            print("Exception Error: ", e)
    return report_sqli_error, report_sqli_boolean


def check_sqli_vuln(res, err):
    for error in err:
        if re.search(error, res):
            return True
    return False


if __name__ == "__main__":
    with open('vuln_detector\sql payload.txt', 'r', encoding='utf8') as f:
        sqli_payloads = f.read().split('\n')
    with open('vuln_detector\sqli_boolean.txt', 'r', encoding='utf8') as f:
        bool_payloads = f.read().split('\n')
    # input_url = 'http://127.0.0.1/DVWA/vulnerabilities/sqli/' #url 주소를 입력
    # input_cookies = {"PHPSESSID": "h7t96vd84gmbih0cvno5jb92pm", "security":"low"} #세션 쿠키를 입력
    input_url = 'https://bwapp.hakhub.net/sqli_2.php'  # url 주소를 입력
    input_cookies = {"PHPSESSID": "kqv10a0sg2b8ij1ujlapcnpui0",
                     "security_level": "0"}  # 세션 쿠키를 입력
    # sqli_url_scan(input_url, input_cookies, sqli_payloads[:9])

    form_list = parse_form(input_url, input_cookies)
    for form in form_list:
        print(Fore.RED + "[[ Form Found ]]")
        print(form)
        sqli_form_scan(input_url, input_cookies,
                       sqli_payloads, bool_payloads, form)
