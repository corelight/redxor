module REDXOR;
# Demonstration script showing example of detection of Linux based C2 backdoor "RedXOR".
# Mitre ATT&CK Technique "Exfiltration Over C2 Channel" https://attack.mitre.org/techniques/T1041/
# Author: Ben Reardon, @benreardon, Corelight Labs https://corelight.com
# Credit: https://www.intezer.com/blog/malware-analysis/new-linux-backdoor-redxor-likely-operated-by-chinese-nation-state-actor/

export {
    redef enum Notice::Type += {
        C2_Traffic_Observed
    };
    redef record HTTP::State += {
        redxor_cookies_seen_so_far: int &default = 0;
    };
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) 
    {
    # In the event the traffic doesn't meet pre conditions, we want to return from the event in the fastest way.
    # This releases resources back to Zeek, which is important for regularly occurring events like this.
    # Keep in mind that this efficiency sometimes comes at a cost of making the detection narrower and more specific. 
    
    # Pre-condition 1: We are only interested in where the method is set, and when it is the POST method - otherwise return straight away.
    # If we don't initially check that the c$http$method exists, there will be (non fatal) run time errors that will fill up reporter.log, so lets avoid that.
    if (!c$http?$method) return;
    # Now check if it's a POST method.
    if (c$http$method != "POST") return;
    
    # Pre-condition 2: all FIVE cookies are contained in the first THREE HTTP trans_depth levels,
    # So for deep HTTP sessions, we can return quickly like so:
    if (c$http$trans_depth > 3) return;
    
    # Pre-condition 3: We're not interested in HTTP sessions with less than four headers. 
    # The sample has exactly four headers, but let's use 4 as a minimum in case a proxy adds headers.
    if (|hlist| < 4) return;
    
    # Now the pre conditions are satisfied, we can continue with the search logic 
    if (c$http$trans_depth == 1) 
        {
        # Check for the FIRST cookie, which is from the CLIENT. 
        # The Cookie is the fourth header in the list, so we look at index of [4] (indexed from 1)
        # If headers are shuffled by proxies, then you'd need to step through each element and look for the cookie,
        # However this is not what we want to demonstrate here. 
        # Also note the value JSESSIONID=0000, which is the malware's "System Information" code
        if (c$http_state$redxor_cookies_seen_so_far == 0 && is_orig && hlist[4]$name == "COOKIE" &&  hlist[4]$value == "JSESSIONID=0000")
            {
            c$http_state$redxor_cookies_seen_so_far = 1;
            return;
            }
        # Now check for the SECOND cookie header, which is set from the SERVER.
        # This is the "Send System Information" C2 command code. 
        # This is first header in the set, so we look at index of [1]
        if (c$http_state$redxor_cookies_seen_so_far == 1 && !is_orig && hlist[1]$name == "SET-COOKIE" &&  hlist[1]$value == "JSESSIONID=0000")
            {
            c$http_state$redxor_cookies_seen_so_far = 2;
            return;
            }
        # A catch-all return statement, as we are finished with the first transaction level - we can return now
        return;
        }

    if (c$http$trans_depth == 2)
        {
        # Now check for the THIRD cookie, which is from the CLIENT.
        # Note the value JSESSIONID=0001 and the content of this POST contains the encoded 
        # system Information that was requested in the previous cookie.
        if (c$http_state$redxor_cookies_seen_so_far == 2 && is_orig && hlist[4]$name == "COOKIE" &&  hlist[4]$value == "JSESSIONID=0001")
            {
            c$http_state$redxor_cookies_seen_so_far = 3;
            return;
            }

        # Now check for the FOURTH cookie, which is from the SERVER.
        # Note the value JSESSIONID=1000, which is the "Ping" command code.
        if (c$http_state$redxor_cookies_seen_so_far == 3 && !is_orig && hlist[1]$name == "SET-COOKIE" &&  hlist[1]$value == "JSESSIONID=1000")
            {
            c$http_state$redxor_cookies_seen_so_far = 4;
            return;
            }
        # A catch all return, as we are finished with the second transaction level - we can return now
        return;
        }
    
    # If the script gets hasn't returned by now, the trans_depth must now be "3"
    # We can now check for the final and FIFTH cookie, which is from the CLIENT.
    # Note the value JSESSIONID=1000, which is the Client/implant's "Pong" to the C2's "Ping" code which we saw in the FOURTH cookie
    if (c$http_state$redxor_cookies_seen_so_far == 4 && is_orig && hlist[4]$name == "COOKIE" &&  hlist[4]$value == "JSESSIONID=1000")
        {
        # Now we've seen this FIFTH cookie, we can raise the notice.
        NOTICE([
            $note=C2_Traffic_Observed,
            $conn=c, 
            $identifier=cat(c$id$orig_h,c$id$resp_h,c$id$resp_h,c$http$uri),
            $suppress_for=60sec,
            $msg="Linux Backdoor 'RedXOR' C2 traffic has been observed (https://attack.mitre.org/techniques/T1041/). More details are available in http.log - search for this same uid. Reference https://www.intezer.com/blog/malware-analysis/new-linux-backdoor-redxor-likely-operated-by-chinese-nation-state-actor/"
        ]);
        }
    }

