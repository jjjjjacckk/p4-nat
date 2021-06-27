echo "START BUILDING!"
cd ~/Desktop/p4-nat-concise/build
p4c --target bmv2 --arch v1model --std p4-16 ../simple_router_16.p4
p4c --target bmv2 --arch v1model --std p4-16 ../simple_router_16.p4 --p4runtime-files ./simple_router_16.p4.p4info.txt
# echo "START MININET!"
cd ~/Desktop/p4-nat-concise/utils
sudo ./build_P2P_Topo.py -j ../build/simple_router_16.json
