# This dictionary contains all the vulnerabily classes which are used to classify the CVE's
# Every class has an array of CWE identifiers which are used to classify the CVE's
cwe_classifications = {
        "information_leakage": [
            "CWE-200",  # Exposure of Sensitive Information to an Unauthorized Actor
            "CWE-319",  # Cleartext Transmission of Sensitive Information
            "CWE-532",  # Insertion of Sensitive Information into Log File
            "CWE-552",  # Files or Directories Accessible to External Parties
        ],
        "validation_error": [
            "CWE-20",  # Improper Input Validation
            "CWE-74",  # Improper Neutralization of Special Elements in Output Used by a Downstream Component
            "CWE-129",  # Improper Validation of Array Index
            "CWE-252",  # Unchecked Return Value
            "CWE-345",  # Insufficient Verification of Data Authenticity
            "CWE-347",  # Improper Verification of Cryptographic Signature
            "CWE-754",  # Improper Check for Unusual or Exceptional Conditions
        ],
        "use_after_free": [
            "CWE-416",  # Use After Free
            "CWE-672",  # Operation on a Resource after Expiration or Release
        ],
        "null_ptr_dereference": [
            "CWE-476",  # NULL Pointer Dereference
        ],
        "uninitialised_memory": [
            "CWE-665",  # Improper Initialization
            "CWE-908",  # Use of Uninitialized Resource
            "CWE-909",  # Missing Initialization of Resource
        ],
        "buffer_overflow": [
            "CWE-119",  # Improper Restriction of Operations within the Bounds of a Memory Buffer
            "CWE-120",  # Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
            "CWE-125",  # Out-of-bounds Read
            "CWE-131",  # Incorrect Calculation of Buffer Size
            "CWE-787",  # Out-of-bounds Write
        ],
        "integer_overflow": [
            "CWE-190",  # Integer Overflow or Wraparound
            "CWE-191",  # Integer Underflow (Wrap or Wraparound)
        ],
        "race_condition": [
            "CWE-362",  # Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
            "CWE-367",  # Time-of-check Time-of-use (TOCTOU) Race Condition
            "CWE-667",  # Improper Locking
        ],
        "div_by_zero": [
            "CWE-369",  # Divide By Zero
        ],
        "type_error": [
            "CWE-704",  # Incorrect Type Conversion or Cast
            "CWE-843",  # Access of Resource Using Incompatible Type ('Type Confusion')
        ],
        "resources_misuse": [
            "CWE-399",  # Resource management errors
            "CWE-401",  # Missing Release of Memory after Effective Lifetime
            "CWE-415",  # Double Free
            "CWE-459",  # Incomplete Cleanup
            "CWE-763",  # Release of Invalid Pointer or Reference
            "CWE-404",  # Improper Resource Shutdown or Release
            "CWE-772",  # Missing Release of Resource after Effective Lifetime
        ],
        "permission_error": [
            "CWE-264",  # Permissions, Privileges, and Access Controls
            "CWE-269",  # Improper Privilege Management
            "CWE-271",  # Privilege Dropping / Lowering Errors
            "CWE-276",  # Incorrect Default Permissions
            "CWE-284",  # Improper Access Control
            "CWE-285",  # Improper Authorization
            "CWE-287",  # Improper Authentication
            "CWE-300",  # Channel Accessible by Non-Endpoint
            "CWE-358",  # Improperly Implemented Security Check for Standard
            "CWE-732",  # Incorrect Permission Assignment for Critical Resource
            "CWE-862",  # Mission Authorization
            "CWE-863",  # Incorrect Authorization
        ],
        "infinite_loop": [
            "CWE-400",  # Uncontrolled Resource Consumption
            "CWE-674",  # Uncontrolled Recursion
            "CWE-770",  # Allocation of Resources Without Limits or Throttling
            "CWE-835",  # Loop with Unreachable Exit Condition ('Infinite Loop')
        ],
        "incorrect_error_handling": [
            "CWE-388",  # Improper error handling
        ],
        "incorrect_code": [
            "CWE-682",  # Incorrect Calculation
        ],
        "other": [
            "CWE-22",  # Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
            "CWE-134",  # Use of Externally-Controlled Format String
            "CWE-203",  # Observable Discrepancy
            "CWE-326",  # Inadequate Encryption Strength
            "CWE-330",  # Use of Insufficiently Random Values
            "CWE-436",  # Interpretation Conflict
            "CWE-617",  # Reachable Assertion
            "CWE-755",  # Improper Handling of Exceptional Conditions
        ]
    }

# The following dictionary contains CVE's and their manually assigned classifications
# The reason they are manually assigned is because either:
# - The CWE was ambiguous, for example:
#    > CWE-189 is a numeric error, which can be classified as an 'integer overflow', a 'divide by zero' or 'other'
#    > CWE-193 is a off-by-one error, which can be classified as a buffer overflow or 'other' (often config error)
#    > CWE classified as: 'NVD-CWE-Other'
# - There where multiple CWE's assigned to a single CVE
# - The classification was invalid or described the possibilities of a possible exploit and not the vulnerability
#
manual_cve_classifiers = {
    "CVE-2010-0307": "incorrect_code",  # Mishandling of edge case can lead to DoS
    "CVE-2010-0415": "validation_error",  # Improper validation of node value of can lead to kernel memory leakage
    "CVE-2010-0437": "null_ptr_dereference",  # Edge case causes a null ptr dereference and can lead to a DoS
    "CVE-2010-0622": "race_condition",  # Improper locking can lead to kernel memory leakage
    "CVE-2010-1085": "div_by_zero",  # Divide By Zero
    "CVE-2010-1162": "other",  # Incorrect control flow can lead to unspecified attack vectors
    "CVE-2010-1643": "null_ptr_dereference",  # Edge case causes a null ptr dereference and can lead to a DoS
    "CVE-2010-2240": "buffer_overflow",  # Memory exhaustion causes the stack and the heap to collide
    "CVE-2010-2955": "validation_error",  # Not verifying properly causes the kernel to leak information
    "CVE-2010-3015": "integer_overflow",  # Integer Overflow
    "CVE-2010-3066": "null_ptr_dereference",  # Edge case causes a null ptr dereference and can lead to a DoS
    "CVE-2010-3086": "incorrect_error_handling",  # Invalid error handling can lead to DoS
    "CVE-2010-3310": "type_error",  # Wrong signedness causes a DoS
    "CVE-2010-3705": "validation_error",  # Not properly validating allows for a remote DoS
    "CVE-2010-3858": "validation_error",  # Not properly validating allows a local user to perform a DoS
    "CVE-2010-3880": "validation_error",  # Not properly validating allows a local user to perform a DoS
    "CVE-2010-4175": "integer_overflow",  # Integer Overflow
    "CVE-2010-4242": "permission_error",  # Incomplete checking of write permission can lead to null ptr dereference
    "CVE-2010-4243": "validation_error",  # Not properly validating allows a local user to perform a DoS
    "CVE-2010-4249": "validation_error",  # Not properly validating allows a local user to perform a DoS

    "CVE-2011-0640": "other",  # Default configuration neglects to inform the user of its possible vulnerability
    "CVE-2011-1023": "incorrect_code",  # Invalid control flow can lead to a DoS
    "CVE-2011-1476": "integer_overflow",  # Integer underflow
    "CVE-2011-1493": "buffer_overflow",  # Buffer underflow leads to heap corruption
    "CVE-2011-1494": "integer_overflow",  # Integer overflow
    "CVE-2011-1746": "integer_overflow",  # Integer overflow causes a buffer overflow
    "CVE-2011-1759": "integer_overflow",  # Integer overflow enables a permission escalation
    "CVE-2011-1767": "incorrect_code",  # Invalid control flow can lead to a DoS
    "CVE-2011-1927": "incorrect_code",  # Invalid control flow can lead to a DoS
    "CVE-2011-2208": "type_error",  # Signedness error enables a kernel memory leak
    "CVE-2011-2209": "type_error",  # Signedness error enables a kernel memory leak
    "CVE-2011-2493": "uninitialised_memory",  # Invalid initialised memory can lead to DoS
    "CVE-2011-2496": "integer_overflow",  # Integer overflow enables a DoS
    "CVE-2011-2521": "incorrect_code",  # A calculation error causes a DoS
    "CVE-2011-2695": "buffer_overflow",  # A off-by-one error causes a out of bounds write followed by a DoS
    "CVE-2011-2699": "information_leakage",  # Invalid ID generation leaks information which can lead to DoS
    "CVE-2011-2905": "validation_error",  # Improper validation of config file can lead to privilege escalation
    "CVE-2011-2942": "null_ptr_dereference",  # Null ptr dereference can lead to DoS
    "CVE-2011-3188": "other",  # Using a weak cryptographic method can lead to communication hijacking
    "CVE-2011-3209": "incorrect_code",  # A calculation error causes a DoS
    "CVE-2011-4131": "incorrect_code",  # Mishandling of bounds causes a DoS
    "CVE-2011-4325": "uninitialised_memory",  # Invalid initialised memory can lead to DoS
    "CVE-2011-4611": "integer_overflow",  # Integer overflow enables a DoS
    "CVE-2011-5321": "null_ptr_dereference",  # Null ptr dereference can lead to DoS

    "CVE-2012-0045": "validation_error",  # Incompletely checking syscall opcodes can lead to DoS
    "CVE-2012-0957": "information_leakage",  # Bad configuration leads to a information leakage
    "CVE-2012-2100": "div_by_zero",  # Divide By Zero allows for remote access
    "CVE-2012-2375": "incorrect_code",  # Invalid hardcoded length causes a DoS
    "CVE-2012-2383": "integer_overflow",  # Integer overflow causes a buffer overflow
    "CVE-2012-2384": "integer_overflow",  # Integer overflow causes a buffer overflow
    "CVE-2012-2744": "null_ptr_dereference",  # Null ptr dereference can lead to DoS
    "CVE-2012-3412": "incorrect_code",  # Mishandling of MSS packet protocol causes a DoS
    "CVE-2012-3375": "incorrect_error_handling",  # Invalid error handling can lead to a DoS
    "CVE-2012-4565": "div_by_zero",  # Divide by zero can lead to a DoS
    "CVE-2012-5517": "null_ptr_dereference",  # Null ptr dereference can lead to DoS
    "CVE-2012-5374": "incorrect_code",  # Wrongly handling files within a cryptographic kernel operation can lead to DoS
    "CVE-2012-5375": "incorrect_code",  # Wrongly handling files within a cryptographic kernel operation can lead to DoS
    "CVE-2012-6701": "integer_overflow",  # Integer overflow can lead to a DoS
    "CVE-2012-6703": "integer_overflow",  # Integer overflow can lead to a DoS

    "CVE-2013-0228": "validation_error",  # Wrongly validating DS register leads to privilege escalation
    "CVE-2013-0311": "other",  # Mishandling descriptors can lead to permission escalation
    "CVE-2013-0913": "integer_overflow",  # Integer overflow leads to a heap buffer overflow
    "CVE-2013-1059": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2013-1826": "incorrect_error_handling",  # Mishandling error state leads to a null ptr dereference
    "CVE-2013-1827": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2013-2094": "type_error",  # Incorrect integer type leads to a privilege escalation
    "CVE-2013-2206": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2013-2546": "information_leakage",  # Insecure copying within cryptographic operation leads to a memory leak
    "CVE-2013-2547": "uninitialised_memory",  # Uninitialised memory leads to a memory leak
    "CVE-2013-2548": "information_leakage",  # Incorrect bounds within cryptographic operation leads to a memory leak
    "CVE-2013-2596": "integer_overflow",  # Integer overflow leads to a privilege escalation
    "CVE-2013-2896": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2013-3301": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2013-4247": "buffer_overflow",  # Invalid looping over filename leads to DoS
    "CVE-2013-4345": "incorrect_code",  # A off by one error causes a random number generator to work improperly
    "CVE-2013-4350": "information_leakage",  # Incomplete encryption of packages lead to information leakage
    "CVE-2013-4483": "incorrect_code",  # Improper handling of a reference counts leads to DoS
    "CVE-2013-4511": "integer_overflow",  # Integer overflow leads to a privilege escalation
    "CVE-2013-4563": "validation_error",  # Improper checking of size can lead to DoS
    "CVE-2013-4579": "information_leakage",  # Improper implementation of cryptographic functions leads to info leakage
    "CVE-2013-6367": "div_by_zero",  # Divide by zero can lead to a DoS
    "CVE-2013-6376": "incorrect_code",  # Improper handling of edge case can lead to DoS
    "CVE-2013-6378": "validation_error",  # Improper checking of imput size can lead to DoS
    "CVE-2013-6432": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2013-7446": "use_after_free",  # Use after free leads to a DoS

    "CVE-2014-0102": "validation_error",  # Improper validation of crypto keyring can lead to DoS
    "CVE-2014-0206": "validation_error",  # Improper validation can lead to a buffer overflow
    "CVE-2014-2889": "incorrect_code",  # Improper calculation of jump destination leads to DoS
    "CVE-2014-3601": "incorrect_code",  # Invalid calculation can lead to DoS
    "CVE-2014-3631": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2014-4171": "race_condition",  # Improper locking can lead to deadlock
    "CVE-2014-4508": "validation_error",  # Improper evaluation of syscall number can lead to DoS
    "CVE-2014-5045": "incorrect_code",  # Invalid reference counting can lead to DoS
    "CVE-2014-7207": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2014-7843": "buffer_overflow",  # Reading 1 past boundary can lead to DoS
    "CVE-2014-8172": "race_condition",  # Race condition can lead to deadlock
    "CVE-2014-8173": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2014-9090": "other",  # Mismanagement of SS register can lead to DoS
    "CVE-2014-9683": "buffer_overflow",  # Buffer overflow can lead to DoS
    "CVE-2014-9715": "type_error",  # Insufficient large data type leads to a null ptr dereference
    "CVE-2014-9731": "buffer_overflow",  # Not large enough buffer can lead to null char dropping and thus info leakage
    "CVE-2014-9803": "permission_error",  # Not properly handling of exec only pages leads to privilege escalation
    "CVE-2014-9904": "integer_overflow",  # Integer overflow leads to a DoS

    "CVE-2015-0274": "incorrect_code",  # Wrong calculation can lead to DoS
    "CVE-2015-0275": "incorrect_code",  # Improper handling of edge case can lead to DoS
    "CVE-2015-1142857": "other",  # Ethernet pause control flow packages can be send to IOV cars
    "CVE-2015-1421": "use_after_free",  # Use after free leads to a DoS
    "CVE-2015-1465": "incorrect_code",  # Wrong calculation can lead to DoS
    "CVE-2015-1573": "resources_misuse",  # Improper cleanup can lead to DoS
    "CVE-2015-1805": "incorrect_error_handling",  # Improper error handling can lead to DoS
    "CVE-2015-2041": "type_error",  # Invalid data type can lead to information leakage
    "CVE-2015-2042": "type_error",  # Invalid data type can lead to information leakage
    "CVE-2015-2922": "validation_error",  # Remote attackers are able through special packets to change the hop limit
    "CVE-2015-2925": "incorrect_code",  # Invalid control flow can lead to privilege escalation
    "CVE-2015-3291": "incorrect_error_handling",  # Improper error handling can lead to DoS
    "CVE-2015-3636": "use_after_free",  # Use after free leads to a DoS
    "CVE-2015-4001": "type_error",  # Invalid integer signedness can lead to DoS
    "CVE-2015-4003": "div_by_zero",  # Divide by zero can lead to DoS
    "CVE-2015-4167": "validation_error",  # Invalid validation can lead to DoS
    "CVE-2015-4177": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2015-4178": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2015-4692": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2015-4700": "incorrect_code",  # Mishandling specific payloads can lead to DoS
    "CVE-2015-5257": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2015-6937": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2015-7513": "div_by_zero",  # Divide by zero can lead to DoS
    "CVE-2015-7515": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2015-7566": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2015-7799": "validation_error",  # Improper validation can lead to a a null ptr dereference
    "CVE-2015-8324": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2015-8543": "validation_error",  # Improper validation can lead to a a null ptr dereference
    "CVE-2015-8746": "uninitialised_memory",  # Improper initialisation can lead to a a null ptr dereference
    "CVE-2015-8787": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2015-8812": "incorrect_error_handling",  # Invalid error handling can lead to a use-after-free
    "CVE-2015-8816": "null_ptr_dereference",  # Null pointer dereference leads to a DoS
    "CVE-2015-8830": "integer_overflow",  # Integer overflow leads to a DoS
    "CVE-2015-8952": "race_condition",  # Invalid locking can lead to DoS

    "CVE-2016-0728": "incorrect_error_handling",  # Improper error handling can cause privilege escalation or DoS
    "CVE-2016-0758": "integer_overflow",  # Integer overflow
    "CVE-2016-0821": "uninitialised_memory",  # Uninitialised memory makes it easier to leak pointer poisons
    "CVE-2016-2053": "incorrect_error_handling",  # Improper error handling
    "CVE-2016-2070": "div_by_zero",  # Divide By Zero
    "CVE-2016-2184": "null_ptr_dereference",  # Null ptr dereference causes a DoS
    "CVE-2016-2185": "null_ptr_dereference",  # Null ptr dereference causes a DoS
    "CVE-2016-2186": "null_ptr_dereference",  # Null ptr dereference causes a DoS
    "CVE-2016-2187": "null_ptr_dereference",  # Null ptr dereference causes a DoS
    "CVE-2016-2188": "null_ptr_dereference",  # Null ptr dereference causes a DoS
    "CVE-2016-2384": "resources_misuse",  # A double free causes a DoS
    "CVE-2016-2543": "validation_error",  # Not verifying FIFO allows for a null dereference and DoS
    "CVE-2016-2782": "null_ptr_dereference",  # Null ptr dereference causes a DoS
    "CVE-2016-3135": "integer_overflow",  # Integer Overflow or Wraparound
    "CVE-2016-3136": "null_ptr_dereference",  # Null ptr dereference causes a DoS
    "CVE-2016-3137": "null_ptr_dereference",  # Null ptr dereference causes a DoS
    "CVE-2016-3138": "null_ptr_dereference",  # Null ptr dereference causes a DoS
    "CVE-2016-3139": "null_ptr_dereference",  # Null ptr dereference causes a DoS
    "CVE-2016-3140": "null_ptr_dereference",  # Null ptr dereference causes a DoS
    "CVE-2016-3672": "resources_misuse",  # Setting the stack to unlimited size disabled ASLR
    "CVE-2016-3689": "other",  # Invalid USB causes a DoS
    "CVE-2016-3951": "resources_misuse",  # A double free causes a DoS
    "CVE-2016-4470": "uninitialised_memory",  # Kernel uses uninitialised data structure which causes a DoS
    "CVE-2016-4557": "use_after_free",  # Use after free can cause privilege escalation or DoS
    "CVE-2016-4558": "incorrect_code",  # mishandling of reference counts causes a DoS (incorrect calculation)
    "CVE-2016-4581": "null_ptr_dereference",  # Null ptr dereference causes a DoS
    "CVE-2016-4794": "use_after_free",  # Use after free can cause undefined behaviour or DoS
    "CVE-2016-4951": "validation_error",  # Not checking if socket exists causes null ptr dereference and DoS
    "CVE-2016-7117": "use_after_free",  # Use After Free
    "CVE-2016-8398": "permission_error",  # Unauthenticated messages are processed
    "CVE-2016-8660": "incorrect_error_handling",  # Improper error handling
    "CVE-2016-2085": "other",  # Using an crypto unsafe mem copy allowed for a timing side-channel

    "CVE-2017-5549": "uninitialised_memory",  # Uninitialised memory is copied to a log file on error
    "CVE-2017-7273": "integer_overflow",  # Integer underflow causes a DoS
    "CVE-2017-16994": "uninitialised_memory",  # Uninitialised memory between huge TLB's causes sensitive data to leak

    "CVE-2018-16658": "type_error",  # Type casting caused a bound check to become invalid, causing it to leak data

    "CVE-2019-7308": "other",  # Out of bounds speculation
    "CVE-2019-7222": "information_leakage",  # Information leak, no further information available
    "CVE-2019-14763": "race_condition",  # Improper Locking
    "CVE-2019-20811": "incorrect_code",  # Mishandling ref counter causes a DoS

    "CVE-2020-26541": "other",  # Not properly using protection mechanisms
    "CVE-2020-29534": "incorrect_code",  # mishandling of ref counts causes a information leakage (wrong calculation)

    # Multiple CWE's are assigned to the following CVE's, manually we have chosen the most accurate classification
    "CVE-2011-0699": "type_error",  # Incorrect signedness allows for a heap buffer overflow
    "CVE-2011-1474": "infinite_loop",  # Bad bounds check in a loop causes a infinite loop
    "CVE-2011-1477": "buffer_overflow",  # Out of bounds access causes a DoS
    "CVE-2011-1833": "race_condition",  # Race condition bypasses a permission validation

    "CVE-2013-4299": "information_leakage",  # Invalid loading of a drive leads to memory leakage

    "CVE-2014-0100": "race_condition",  # Race conditions makes a use-after-free possible
    "CVE-2014-9914": "race_condition",  # Race conditions makes a use-after-free possible

    "CVE-2015-7312": "race_condition",  # Race conditions makes a use-after-free possible
    "CVE-2015-7550": "race_condition",  # Race conditions makes a null reference possible
    "CVE-2015-8963": "race_condition",  # Race conditions makes a null reference possible

    "CVE-2016-0723": "race_condition",  # Race conditions makes a use-after-free possible
    "CVE-2016-10150": "use_after_free",  # Use-after-free makes a privilege escalation possible
    "CVE-2016-10200": "race_condition",  # Race condition makes a privilege escalation and use-after-free possible
    "CVE-2016-10906": "race_condition",  # Race condition makes a use-after-free possible
    "CVE-2016-3841": "other",  # Mishandling of option flag makes a privilege escalation and use-after-free possible
    "CVE-2016-6187": "validation_error",  # Lack of validation makes a privilege escalation possible
    "CVE-2016-6516": "race_condition",  # Race condition makes a buffer overflow possible (double fetch)
    "CVE-2016-7911": "race_condition",  # Race condition makes a privilege escalation and use-after-free possible
    "CVE-2016-7914": "incorrect_code",  # Improper Handling of edge case makes a kernel memory leak possible
    "CVE-2016-7917": "validation_error",  # Lack of validation makes a kernel memory leak possible
    "CVE-2016-8630": "null_ptr_dereference",  # Null pointer dereference makes a DoS possible
    "CVE-2016-8632": "validation_error",  # Lack of validation makes a privilege escalation or buffer overflow possible
    "CVE-2016-8633": "validation_error",  # Lack of validation makes remote code execution possible
    "CVE-2016-8650": "validation_error",  # Lack of validation makes a DoS possible
    "CVE-2016-8655": "race_condition",  # Race condition makes a privilege escalation and use-after-free possible
    "CVE-2016-9083": "integer_overflow",  # Bypassing of an integer overflow check makes DoS possible
    "CVE-2016-9120": "race_condition",  # Race condition makes a privilege escalation and use-after-free possible
    "CVE-2016-9191": "validation_error",  # Lack of validation makes a DoS possible
    "CVE-2016-9794": "race_condition",  # Race condition makes a use-after-free possible
    "CVE-2016-9806": "race_condition",  # Race condition makes a use-after-free possible

    "CVE-2017-0620": "validation_error",  # Lack of validation makes a privilege escalation possible
    "CVE-2017-1000252": "validation_error",  # Lack of validation makes a DoS possible
    "CVE-2017-15265": "race_condition",  # Race condition makes a use-after-free possible
    "CVE-2017-2584": "other",  # Improper instruction emulation makes a use-after-free possible
    "CVE-2017-2636": "race_condition",  # Race condition makes a privilege escalation and double-free possible
    "CVE-2017-5986": "race_condition",  # Race condition makes DoS possible
    "CVE-2017-6346": "race_condition",  # Race condition makes a use-after-free possible
    "CVE-2017-6874": "race_condition",  # Race condition makes a use-after-free possible
    "CVE-2017-7294": "validation_error",  # Lack of validation makes a integer overflow and buffer overflow possible
    "CVE-2017-7374": "use_after_free",  # Use after free makes a DoS possible
    "CVE-2017-7542": "integer_overflow",  # Integer overflow makes a DoS possible

    "CVE-2018-13096": "buffer_overflow",  # Buffer overflow occurs when a crafted image is inserted
    "CVE-2018-13097": "buffer_overflow",  # Buffer overflow occurs when a crafted image is inserted
    "CVE-2018-14610": "validation_error",  # Lack of validation makes a buffer overflow possible
    "CVE-2018-18559": "race_condition",  # Race condition makes a use-after-free possible
    "CVE-2018-20836": "race_condition",  # Race condition makes a use-after-free possible
    "CVE-2018-5344": "incorrect_code",  # Improper Handling of Exceptional Conditions makes a use-after-free possible
    "CVE-2018-5873": "race_condition",  # Race condition makes a use-after-free possible
    "CVE-2018-7566": "race_condition",  # Race condition makes a use-after-free possible

    "CVE-2019-11810": "null_ptr_dereference",  # Null ptr dereference makes a use-after-free possible
    "CVE-2019-13233": "race_condition",  # Race condition makes a use-after-free possible
    "CVE-2019-14283": "validation_error",  # Lack of validation makes a buffer overflow and integer overflow possible
    "CVE-2019-14898": "race_condition",  # Improper locking makes information leakage possible
    "CVE-2019-19319": "use_after_free",  # Use after free possible while mounting an ext4 drive

    "CVE-2020-10757": "permission_error",  # Bad handling of an huge page leads to privilege escalation
    "CVE-2020-27825": "race_condition",  # Race condition makes a use-after-free possible
    "CVE-2020-29374": "race_condition",  # Race condition can cause a privilege escalation on memory
    "CVE-2020-29660": "race_condition",  # Race condition makes a use-after-free possible
    "CVE-2020-29661": "race_condition",  # Race condition can cause a privilege escalation on memory
}


# This function classifies an CVE
# This is done by first checking if it has a manual assignment
#   If yes, then it extracts the manual assignment from the dictionary
#   If not, then it attempts to manually assign the CVE
#      If this could not be done, then an error is printed and the execution is terminated
def classify_on_cwe(cve, cwes):
    if "manual" in cwes:
        if cve in manual_cve_classifiers:
            return manual_cve_classifiers[cve]
        else:
            print("Error! No manual CVE classification has been found!")
            print(cve.split('-'), cwes)
            exit(0)

    else:
        if len(cwes) > 1:
            print("Error! Multiple CWEs have been found!")
            print(cve, cwes)
            exit(0)
        for cwe in cwes:
            for key, c in cwe_classifications.items():
                if cwe in c:
                    return key
        print("Error! No automatic CVE classification has been found!")
        print(cve, cwes)
        exit(0)
