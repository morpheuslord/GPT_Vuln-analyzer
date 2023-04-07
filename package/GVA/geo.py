from subprocess import run


def geoip(key, target):
    url = "https://api.ipgeolocation.io/ipgeo?apiKey={a}&ip={b}".format(
        a=key, b=target)
    content = run("curl {}".format(url))
    return content
