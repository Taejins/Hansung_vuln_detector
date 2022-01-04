import requests
from bs4 import BeautifulSoup, SoupStrainer

target_domain = "https://shop.hakhub.net"
# target_domain = "https://bwapp.hakhub.net/"
# target_domain = "http://127.0.0.1/dvwa/"


    

def discover_directory(url, cookies, gui):
    domain = url[:-1] if url[-1] == "/" else url
    results = set()
    hrefs = set()
    try:
        content = requests.get(domain, cookies= cookies).content
    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        print(f"Requets error: {e}")
    for link in BeautifulSoup(
        content, features="html.parser", parse_only=SoupStrainer("a")
    ):
        if hasattr(link, "href"):
            try:
                path = link["href"]
                if (
                    path.startswith("#")
                    or path.startswith("javascript")
                    or path.endswith(".jpg")
                    or path.endswith(".png")
                    or path.endswith(".css")
                    or path.endswith(".js")
                    or path.startswith("?")
                    or "/#" in path
                ):
                    continue
                elif path.startswith("/") :
                    hrefs.add(f"{domain}{path}")
                elif domain not in path and path[:4] != "http":
                    hrefs.add(f"{domain}/{path}")
                else:
                    hrefs.add(path)
            except KeyError:
                pass
            except Exception as e:
                print(f"Error when parsing: {e}")
    for href in hrefs:
        if href.startswith(domain):
            gui.output_str.emit(f" [+] {href}" )
            results.add(href)
    return list(results)


if __name__ == "__main__":
    
    input_cookies = {
        "PHPSESSID" : "89s8stgl0d1d5627uuud5buvj8",
        "security" : "low"
    }
    
    discover_directory(target_domain, input_cookies)
    # links = copy.deepcopy(results)
    # print(f"Start Scanning on {len(links)} Links...")
    # for link in links:
    #     print(f"Searching on ... {link}")
    #     links.add(link)
    #     discover_directory(link, input_cookies)
