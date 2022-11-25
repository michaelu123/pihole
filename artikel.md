# pihole und googleadservices
Nachdem ich pihole out of the box installiert und bei der Fritzbox als DNS-Server eingetragen hatte, kamen sofort Beschwerden, daß Google-Anzeigen blockiert wurden. Und auch ich selber klickte ständig auf die Anzeigen, obwohl ich es eigentlich besser wußte. Eine Suche nach "pihole googleadservices" förderte eine Menge gleichartiger Klagen und eine Vielzahl an Lösungsvorschlägen zutage. Diese fallen in die 3 Kategorien:
-   Funktioniert wie beabsichtigt
-   Schau auf die Suchergebnisse unterhalb der Anzeigen
-   Ändere die Pihole-Konfiguration

Letzterer Ansatz reicht vom einfachen whitelisting von googleadservices bis zu speziellen Regeln für jedes Endgerät im Haus.

Wenn man sich in Chrome eine von pihole gesperrte URL (ja ich weiß, eigentlich ist der DNS-Record gesperrt) anschaut, wenn man z.B. nach "Heise c't" googelt und auf die Anzeige "c't Magazin im Abo" klickt, bekommt man die Fehlermeldung "Die Webseite ist nicht erreichbar" und "Die Server-IP-Adresse von www.googleadservices.com wurde nicht gefunden". Als URL wird 

        https://www.googleadservices.com/pagead/aclk?XXX&adurl=https://shop.heise.de/zeitschriften-abo/ct/%3FLPID%3D27061_CT000002_16240_3_23%26wt_mc%3Dsea.abo.ct.brand_abo.google.brand.heise%2520c%27t

wobei XXX für eine Menge von kryptischen Zeichen steht. Aber immerhin steht die URL des Heise-Shops hinter adurl=. Das hat mich auf die Idee gebracht, einfach alles vor adurl= wegzuwerfen. Von Hand die URL zu editieren ist sehr mühsam, weil es wirklich viele Zeichen sind, für die oben XXX steht. Aber es gibt ja Chrome Extensions, und so habe ich erst einmal versucht, eine Chrome Extension zu finden, die das schon implementiert.

Da ich keine finden konnte, habe ich mich selber etwas mit Chrome Extensions beschäftigt, und bin dabei auf die API declarativeNetRequest gestoßen, siehe https://developer.chrome.com/docs/extensions/reference/declarativeNetRequest/, mit der man Netzwerk-Requests (URLs) modifizieren kann, ohne daß die Extension den Request abfängt oder anschaut. Normalerweise schreibt man in einer Extension Code, der die URLs oder die transferierten Daten modifiziert, und da dieser Code im Prinzip alles mitliest, was der Browser anzeigt, müssen Extensions speziellen Sicherheitsanforderungen genügen. Die declarativeNetRequests funktionieren aber so, daß der Browser nur die Regeln für die URL-Modifikationen aus der Extension holt und die Regeln dann selber abarbeitet.

Damit konnte ich eine sehr einfache Extension schreiben, die weder HTML noch Code enthält, und die Regeln mittels regular expressions formuliert, mit denen eine URL in eine andere umgewandelt wird, in diesem Fall also alles vor adurl= wegwirft. Es gibt aber noch ein paar Spezialfälle. Es gibt URLs, in denen hinter adurl= eine weitere Adserver-URL steht, anscheinend beschränkt auf die Adserver doubleclick und clickserve. Bei diesen Adservern steht die uns interessierende URL dann hinter _clickid_ oder ds_dest_url. Und manchmal sehen die URLs auch ganz anders aus, ohne daß die uns interessierende URL irgendwo als Klartext steht, womit dieser Ansatz dann versagt. Sie sind aber selten.

Natürlich funktioniert dieser Ansatz auch nur solange, wie die Adserver-URL die eigentliche URL als Klartext enthält. Mit den Regeln von declarativeNetRequest kann man eine neue URL aus Teilen der alten URL zusammensetzen, die Teile aber selber nicht modifizieren, insbesondere nicht mit base64 dekodieren, oder unescapen. Wenn die uns interessierende URL noch Parameter enthält, ist das Fragezeichen als %3F codiert, und wenn das nicht decodiert wird, führt die URL zu einem 404-Fehler. Deshalb schneiden die Regeln in der Extension nicht nur alles vor adurl= weg, sondern auch alles nach %3F. Die URL wird also immer ohne Parameter aufgerufen.

Ein anderes Problem ist noch, daß der Chrome-Browser auf Android keine Extensions kennt. Ausgerechnet das Gerät, mit dem meine Frau bevorzugt im Internet surft, kann also leider mit dieser Extension nichts anfangen, und die oben genannten Beschwerden bleiben bestehen :-( .

Die Extension besteht aus den zwei Dateien manifest.json und rules.json. Man packt sie in ein beliebiges Verzeichnis, ruft dann chrome://extensions auf, und klickt auf "Entpackte Erweiterung laden", um sie den Extensions hinzuzufügen.

Die 4 Regeln sind schnell erklärt: die letzte Regel redirected zu der URL, die nach adurl= steht. Die dritte Regel redirected zu der URL, die zwischen adurl= und %3F steht. Die zweite redirected, wenn in der URL ein clickserve.dartsearch.net vorkommt, zu der URL, die zwischen ds_dest_url%3D und %3F steht. Die erste entsprechend.

Die Datei manifest.json besagt, daß die Extension googleadservices betrifft, und die Regeln in der Datei rules.json stehen:

        {
            "name": "pihole_googleads",
            "description": "make google ads usable for Pihole",
            "version": "1.0",
            "manifest_version": 3,
            "declarative_net_request": {
                "rule_resources": [{
                    "id": "ruleset",
                    "enabled": true,
                    "path": "rules.json"
                }]
            },
            "permissions": [
                "declarativeNetRequest"
            ],
            "host_permissions": [
                "https://www.googleadservices.com/*"
            ]
        }

Die Datei rules.json enthält die oben beschriebenen 4 Regeln:

        [
            {
                "id": 1,
                "priority": 2,
                "action": {
                    "type": "redirect",
                    "redirect": {
                        "regexSubstitution": "\\1"
                    }
                },
                "condition": {
                    "regexFilter": "^https://www.googleadservices.com/.*adurl=https://ad.doubleclick.net/.*_clickid_%3F(.*)%3F.*",
                    "resourceTypes": [ "main_frame" ]
                }
            },
            {
                "id": 2,
                "priority": 2,
                "action": {
                    "type": "redirect",
                    "redirect": {
                        "regexSubstitution": "\\1"
                    }
                },
                "condition": {
                    "regexFilter": "^https://www.googleadservices.com/.*adurl=https://clickserve.dartsearch.net/.*ds_dest_url%3D(.*)%3F.*",
                    "resourceTypes": [ "main_frame" ]
                }
            },
            {
                "id": 3,
                "priority": 1,
                "action": {
                    "type": "redirect",
                    "redirect": {
                        "regexSubstitution": "\\1"
                    }
                },
                "condition": {
                    "regexFilter": "^https://www.googleadservices.com/.*adurl=(.*)%3F.*",
                    "resourceTypes": [ "main_frame" ]
                }
            },
            {
                "id": 4,
                "priority": 1,
                "action": {
                    "type": "redirect",
                    "redirect": {
                        "regexSubstitution": "\\1"
                    }
                },
                "condition": {
                    "regexFilter": "^https://www.googleadservices.com/.*adurl=(.*)",
                    "resourceTypes": [ "main_frame" ]
                }
            }
        ]
