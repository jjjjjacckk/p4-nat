# P4-nat

## Credit
This repository is forked from [blizzardplus's p4-nat](https://github.com/blizzardplus/p4-nat)

I found out that there are a lot of deprecated functions and features, so I rewrite basically all the framework for Project

## Introduction
This is a Project proposing an solution for `Symmetric NAT Traversal` using p4 based SDN.

I compared my solution with which proposed by Waseda University in this [paper](https://www.semanticscholar.org/paper/A-New-Method-for-Symmetric-NAT-Traversal-in-UDP-and-Yamada-Yoshida/0004757d7fc7683706b0decd8ec6ee6bdf638cc2?p2df)

# Getting started
- [ Environment ] 
    - Ubuntu 16.04 LTS
        > Follow Official P4-Tutorial Environment [setup](https://github.com/p4lang/tutorials) 
- [ Compilation ]
    1. Compile p4 porgram:
        ```bash
        $ cd ~/Desktop/p4-nat/build
        $ p4c --target bmv2 --arch v1model --std p4-16 ../simple_router_16.p4
        $ p4c --target bmv2 --arch v1model --std p4-16 ../simple_router_16.p4 --p4runtime-files ./simple_router_16.p4.p4info.txt
        ```
    2. Start the BMv2 CLI:
        ```bash 
        $ cd ~/Desktop/p4-nat/utils
        $ sudo ./build_P2P_Topo.py -j ../build/simple_router_16.json
        ```
- [ Method1 ] My Solution
    1. In CLI:
        - Open terminal of `h1`, `h3`, and `server1` 
            ```bash 
            $ xterm h1 h3 server1
            ``` 
    2. For Host:
        - Host : `h1`, `h2`, `h3`, `h4`
        - Usage: `./host_method1.py <through server> <whoAmI> <whom2connect> <Port on host>`
        - (e.g.) 
            ```
                h1 -----> server1 -----> h3
            ```
            ```bash
            # On h1
            $ cd ../test
            $ ./host_method1.py server1 h1 h3 33333 

            # On h3
            $ cd ../test
            $ ./host_method1.py server1 h3 h1 33333 
            ```
    5. For Server:
        - Server : `server1`, `server2`
        - Usage: `./server_method1.py <server>`
        - (e.g.) 
            ```
                h1 -----> server1 -----> h3
            ```
            ```bash
            # On server1
            $ cd ../test
            $ ./server_method1.py server1
            ```
- [ Method2 ]
    1. In CLI:
        - Open terminal of `h1`, `h3`, and `server1` 
            ```bash 
            $ xterm h1 h1 h3 h3 server1 server2
            ``` 
    2. For Host:
        - Host : `h1`, `h2`, `h3`, `h4`
        - Usage: `./host_method1.py <whoAmI> <whom2connect>`
        - (e.g.) 
            ```
                h1 -----> server1 -----> h3
                |                        ^
                |                        |
                --------> server2 --------
            ```
            ```bash
            # On h1
            $ cd ../test
            $ ./host_method1.py h1 h3

            # On h3
            $ cd ../test
            $ ./host_method1.py h3 h1
            ```
    5. For Server:
        - Server : `server1`, `server2`
        - Usage: `./<server>_method1.py `
        - (e.g.) 
            ```
                h1 -----> server1 -----> h3
                |                        ^
                |                        |
                --------> server2 --------
            ```
            ```bash
            # On server1
            $ cd ../test
            $ ./server1_method2.py

            # On server2
            $ cd ../test
            $ ./server2_method2.py
            ```