import shodan
import pandas as pd
import yaml
from yaml import SafeLoader
from datetime import datetime

def get_api_key():

    with open(
            "shodan_api.yaml") as f:
        conf = yaml.load(f, Loader=SafeLoader)

    apikey = conf['shodan_api']['api_key']
    return apikey


def get_shodan_data(query_product, query_city,  query_org):
    query_org_list = []
    query_product_list = []

    _shodan_region = []
    product = []

    http_status = []
    http_redirects = []
    http_title = []
    http_robots = []
    http_server = []
    http_host = []
    http_location = []
    http_components = []

    os = []
    tags = []
    org = []
    isp = []
    cpe23 = []
    asn = []

    ssl_versions = []
    ssl_tlsext = []
    ssl_cert_fingerprint = []
    ssl_cert_issued = []
    ssl_cert_expires = []
    ssl_cert_expired = []
    ssl_cert_issuer = []
    ssl_cert_subject = []
    ssl_cipher = []
    ssl_trust = []

    hostnames = []
    location_city = []
    location_country_name = []
    timestamp = []
    domains = []
    port = []
    transport = []
    ip_str = []

    # Configuration
    API_KEY = get_api_key()
    # Setup the api
    api = shodan.Shodan(API_KEY)

    # Perform the search
    query = str(query_product) + " city:\"" + str(query_city) + "\"" + " org:\"" + str(query_org) + "\""

    print(query)

    result = api.search(query)

    # Loop through the matches and print each IP
    for service in result['matches']:

        query_org_list.append(query_org)
        query_product_list.append(query_product)

        try:
            product.append(service["product"])
        except KeyError:
            product.append("no information")

        try:
            http_status.append(service["http"]["status"])
        except KeyError:
            http_status.append("no information")

        try:
            http_redirects.append(service["http"]["redirects"])
        except KeyError:
            http_redirects.append("no information")

        try:
            http_title.append(service["http"]["title"])
        except KeyError:
            http_title.append("no information")

        try:
            http_robots.append(service["http"]["robots"])
        except KeyError:
            http_robots.append("no information")

        try:
            http_server.append(service["http"]["server"])
        except KeyError:
            http_server.append("no information")

        try:
            http_host.append(service["http"]["host"])
        except KeyError:
            http_host.append("no information")

        try:
            http_location.append(service["http"]["location"])
        except KeyError:
            http_location.append("no information")

        try:
            http_components.append(service["http"]["components"])
        except KeyError:
            http_components.append("no information")

        try:
            os.append(service["os"])
        except KeyError:
            os.append("no information")

        try:
            tags.append(service["tags"])
        except KeyError:
            tags.append("no information")

        try:
            org.append(service["org"])
        except KeyError:
            org.append("no information")

        try:
            isp.append(service["isp"])
        except KeyError:
            isp.append("no information")

        try:
            cpe23.append(service["cpe23"])
        except KeyError:
            cpe23.append("no information")

        try:
            asn.append(service["asn"])
        except KeyError:
            asn.append("no information")

        try:
            ssl_versions.append(service["ssl"]["versions"])
        except KeyError:
            ssl_versions.append("no information")

        try:
            ssl_tlsext.append(service["ssl"]["tlsext"])
        except KeyError:
            ssl_tlsext.append("no information")

        try:
            ssl_cert_fingerprint.append(service["ssl"]["cert"]["fingerprint"])
        except KeyError:
            ssl_cert_fingerprint.append("no information")

        try:
            ssl_cert_issued.append(
                datetime.strptime(service["ssl"]["cert"]["issued"], "%Y%m%d%H%M%SZ").strftime("%Y-%m-%d %H:%M:%S UTC"))
        except KeyError:
            ssl_cert_issued.append("no information")

        try:
            ssl_cert_expires.append(
                datetime.strptime(service["ssl"]["cert"]["expires"], "%Y%m%d%H%M%SZ").strftime("%Y-%m-%d %H:%M:%S UTC"))
        except KeyError:
            ssl_cert_expires.append("no information")

        try:
            ssl_cert_expired.append(service["ssl"]["cert"]["expired"])
        except KeyError:
            ssl_cert_expired.append("no information")

        try:
            ssl_cert_issuer.append(service["ssl"]["cert"]["issuer"])
        except KeyError:
            ssl_cert_issuer.append("no information")

        try:
            ssl_cert_subject.append(service["ssl"]["cert"]["subject"])
        except KeyError:
            ssl_cert_subject.append("no information")

        try:
            ssl_cipher.append(service["ssl"]["cipher"])
        except KeyError:
            ssl_cipher.append("no information")

        try:
            ssl_trust.append(service["ssl"]["trust"])
        except KeyError:
            ssl_trust.append("no information")

        try:
            hostnames.append(service["hostnames"])
        except KeyError:
            hostnames.append("no information")

        try:
            location_city.append(service["location"]["city"])
        except KeyError:
            location_city.append("no information")

        try:
            location_country_name.append(service["location"]["country_name"])
        except KeyError:
            location_country_name.append("no information")

        try:
            timestamp.append(service["timestamp"])
        except KeyError:
            timestamp.append("no information")

        try:
            domains.append(service["domains"])
        except KeyError:
            domains.append("no information")

        try:
            port.append(service["port"])
        except KeyError:
            port.append("no information")

        try:
            transport.append(service["transport"])
        except KeyError:
            transport.append("no information")

        try:
            ip_str.append(service["ip_str"])
        except KeyError:
            ip_str.append("no information")

    df_data = {

        "query_org": query_org_list,
        "Query Product": query_product_list,
        "product": product,
        "http_status": http_status,
        "http_redirects": http_redirects,
        "http_title": http_title,
        "http_robots": http_robots,
        "http_server": http_server,
        "http_host": http_host,
        "http_location": http_location,
        "http_components": http_components,
        "os": os,
        "tags": tags,
        "org": org,
        "isp": isp,
        "cpe23": cpe23,
        "asn": asn,
        "ssl_versions": ssl_versions,
        "ssl_tlsext": ssl_tlsext,
        "ssl_cert_fingerprint": ssl_cert_fingerprint,
        "ssl_cert_issued": ssl_cert_issued,
        "ssl_cert_expires": ssl_cert_expires,
        "ssl_cert_expired": ssl_cert_expired,
        "ssl_cert_issuer": ssl_cert_issuer,
        "ssl_cert_subject": ssl_cert_subject,
        "ssl_cipher": ssl_cipher,
        "ssl_trust": ssl_trust,
        "hostnames": hostnames,
        "location_city": location_city,
        "location_country_name": location_country_name,
        "timestamp": timestamp,
        "domains": domains,
        "port": port,
        "transport": transport,
        "ip_str": ip_str

    }

    df = pd.DataFrame(df_data)

    return df

def main():

    inputfile = input("Enter excel file: ")

    df_input = pd.read_csv(inputfile)

    df_list = []

    for index, row in df_input.iterrows():

        df = get_shodan_data(row["Product"], row["City"], row["Org"])

        df_list.append(df)

    df_concat = pd.concat(df_list)

    df_concat.to_excel("shodan_result.xlsx" , index=False)
    
    print("Query Completed !!!")

if __name__ == "__main__":
    main()
