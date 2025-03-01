import urllib.parse
import argparse

class WAFBypasser:
    def __init__(self, payload):
        self.payload = payload
        self.techniques = {
            'url_encode': self.url_encode,
            'unicode_escape': self.unicode_escape,
            'case_variation': self.case_variation,
            'comment_insertion': self.comment_insertion,
            'string_splitting': self.string_splitting,
            'hex_encoding': self.hex_encoding,
            'mixed_encoding': self.mixed_encoding,
        }
        self.enabled_techniques = []

    def enable(self, techniques):
        for technique in techniques:
            if technique in self.techniques:
                self.enabled_techniques.append(technique)
            else:
                raise ValueError(f"Unknown technique: {technique}")

    def generate(self):
        results = []
        for technique in self.enabled_techniques:
            method = self.techniques[technique]
            transformed = method(self.payload)
            results.append((technique, transformed))
        return results

    def url_encode(self, payload):
        return urllib.parse.quote(payload)
    
    def unicode_escape(self, payload):
        return ''.join([f'\\u{ord(c):04x}' for c in payload])
    
    def case_variation(self, payload):
        return ''.join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)])
    
    def comment_insertion(self, payload):
        return '/**/'.join(payload)
    
    def string_splitting(self, payload):
        mid = len(payload) // 2
        return f"{payload[:mid]}||{payload[mid:]}"
    
    def hex_encoding(self, payload):
        return f"0x{payload.encode().hex()}"
    
    def mixed_encoding(self, payload):
        temp = self.url_encode(payload)
        temp = self.case_variation(temp)
        temp = self.comment_insertion(temp)
        return temp

def main():
    parser = argparse.ArgumentParser(description="WAF Bypass Payload Generator")
    parser.add_argument("-p", "--payload", required=True, help="Original payload to transform")
    parser.add_argument("-t", "--techniques", nargs="+", default=["all"], 
                        choices=["all", "url_encode", "unicode_escape", "case_variation",
                                  "comment_insertion", "string_splitting", "hex_encoding",
                                  "mixed_encoding"],
                        help="Bypass techniques to apply")
    args = parser.parse_args()

    bypasser = WAFBypasser(args.payload)
    
    if "all" in args.techniques:
        techniques = list(bypasser.techniques.keys())
    else:
        techniques = args.techniques
    
    bypasser.enable(techniques)
    results = bypasser.generate()

    print(f"\nOriginal Payload: {args.payload}\n")
    print("Generated Payloads:")
    for technique, payload in results:
        print(f"\n[{technique.upper()}]")
        print(payload)

if __name__ == "__main__":
    main()
