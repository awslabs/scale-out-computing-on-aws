
# Begin: XDummy Driver
function install_x_dummy_driver() {
  # To use console sessions on Linux servers that do not have a dedicated GPU, ensure that the Xdummy driver is installed and properly configured.
  # The XDummy driver allows the X server to run with a virtual framebuffer when no real GPU is present.
  # Refer: https://docs.aws.amazon.com/dcv/latest/adminguide/setting-up-installing-linux-prereq.html#gpu-xdummy

  yum install -y xorg-x11-drv-dummy
  echo -n 'Section "Device"
    Identifier "DummyDevice"
    Driver "dummy"
    Option "ConstantDPI" "true"
    Option "IgnoreEDID" "true"
    Option "NoDDC" "true"
    VideoRam 2048000
EndSection

Section "Monitor"
    Identifier "DummyMonitor"
    HorizSync   5.0 - 1000.0
    VertRefresh 5.0 - 200.0
    Modeline "1920x1080" 23.53 1920 1952 2040 2072 1080 1106 1108 1135
    Modeline "1600x900" 33.92 1600 1632 1760 1792 900 921 924 946
    Modeline "1440x900" 30.66 1440 1472 1584 1616 900 921 924 946
    ModeLine "1366x768" 72.00 1366 1414 1446 1494  768 771 777 803
    Modeline "1280x800" 24.15 1280 1312 1400 1432 800 819 822 841
    Modeline "1024x768" 18.71 1024 1056 1120 1152 768 786 789 807
EndSection

Section "Screen"
    Identifier "DummyScreen"
    Device "DummyDevice"
    Monitor "DummyMonitor"
    DefaultDepth 24
    SubSection "Display"
        Viewport 0 0
        Depth 24
        Modes "1920x1080" "1600x900" "1440x900" "1366x768" "1280x800" "1024x768"
        Virtual 1920 1080
    EndSubSection
EndSection
' > /etc/X11/xorg.conf
}
# End: XDummy Driver