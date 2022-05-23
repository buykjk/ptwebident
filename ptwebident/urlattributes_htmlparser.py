from html.parser import HTMLParser


class URLAttributesHTMLParser(HTMLParser):
    """Parser that extracts URLs from HTML attributes"""

    # HTML tags with their corresponding attributes, which may contain URLs
    # Source: https://stackoverflow.com/questions/2725156/complete-list-of-html-tag-attributes-which-have-a-url-value
    _url_tags_attrs = {
        'a': ['href'],
        'applet': ['archive', 'codebase'],
        'area': ['href'],
        'audio': ['src'],
        'base': ['href'],
        'blockquote': ['cite'],
        'body': ['background'],
        'button': ['formaction'],
        'command': ['icon'],
        'del': ['cite'],
        'embed': ['src'],
        'form': ['action'],
        'frame': ['longdesc', 'src'],
        'head': ['profile'],
        'html': ['manifest'],
        'iframe': ['longdesc', 'src'],
        'img': ['longdesc', 'usemap', 'src', 'srcset'],
        'input': ['formaction', 'usemap', 'src'],
        'ins': ['cite'],
        'link': ['href'],
        'object': ['classid', 'usemap', 'data', 'archive', 'codebase'],
        'q': ['cite'],
        'script': ['src'],
        'source': ['src', 'srcset'],
        'track': ['src'],
        'video': ['poster', 'src'],
        'meta': ['content'] # only if 'property' is "og:url" or "og:image"
    }
    
    # Source: https://ogp.me/
    _meta_url_properties = [
        "og:url",
        "og:image",
        "og:video",
        "og:audio"
    ]


    def __init__(self, *, convert_charrefs: bool = ...) -> None:
        super().__init__(convert_charrefs=convert_charrefs)
        self.urls_found : set[str] = set()
    

    # override
    def handle_starttag(self, tag: str, attrs) -> None:
        """Custom attribute handler, parses URL attributes"""

        if tag in self._url_tags_attrs:
            url_attrs = self._url_tags_attrs[tag]

            # Special case for meta tag
            if tag == 'meta':
                add_content = False
                content_data = ''

                for attr in attrs:
                    if attr[0] == 'property' and attr[1] in self._meta_url_properties:
                        add_content = True
                    
                    if attr[0] == 'content':
                        content_data = attr[1]

                if add_content and content_data is not None and content_data != '':
                    self.urls_found.add(content_data)

            else:
                # attr = (name, value)
                for attr in attrs:
                    if attr[0] in url_attrs and attr[1] != None and len(attr[1]) != 0:
                        self.urls_found.add(attr[1])