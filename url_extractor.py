import re
import tldextract

def analyze_urls(url_list_or_text):
    print("\n=== DEBUG START: URL EXTRACTOR ===")
    print(f"Input type received: {type(url_list_or_text)}")
    
    if isinstance(url_list_or_text, str):
        print(f"Text length to scan: {len(url_list_or_text)} characters")
        print("First 150 characters of the text we are scanning:")
        print(repr(url_list_or_text[:150]))  # repr() shows hidden newlines and spaces
        
        # A much broader regex to catch almost any URL format
        url_pattern = re.compile(r'(?:https?://|www\.)[a-zA-Z0-9./_?=&%-]+', re.IGNORECASE)
        raw_urls = list(set(re.findall(url_pattern, url_list_or_text)))
    else:
        print(f"List length to scan: {len(url_list_or_text)} items")
        raw_urls = list(set(url_list_or_text))
        
    print(f"Raw URLs successfully found: {raw_urls}")
    
    analyzed_urls = []
    for url in raw_urls:
        # tldextract requires a protocol to parse 'www.' properly
        parse_url = 'http://' + url if url.lower().startswith('www.') else url
        extracted = tldextract.extract(parse_url)
        
        analysis = {
            "original_url": url,
            "subdomain": extracted.subdomain,
            "domain": extracted.domain,
            "suffix": extracted.suffix,
            "is_secure": url.lower().startswith('https://')
        }
        analyzed_urls.append(analysis)
        
    print("=== DEBUG END ===\n")
    return analyzed_urls