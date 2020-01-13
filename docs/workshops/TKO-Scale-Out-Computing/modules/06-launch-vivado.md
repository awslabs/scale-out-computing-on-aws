# Lab 4: Launch Vivado GUI

## Launch the Vivado CAD Tool

Now that your remote desktop is set up, you can launch the Vivado Design Suite (included in the AWS FPGA Developer AMI).  The goal with this lab is to evaluate the remote visualization experience using a graphically intensive Computer-Aided Design (CAD) tool.

## Step 1: Log into your session

By now your remote desktop session should be ready and you should see the following under **Your Session #1**:

![](../../../imgs/access-7.png)

1. Click **Open Session directly on a browser** to log into the remote desktop session in your new cluster using the username and password you created in the steps above.

    !!! note
        You can also access the session with the NICE DCV native clients, which are available for Mac, Linux, and Windows from https://download.nice-dcv.com

1. To launch Vivado, start a new terminal session by going to **Applications → Favorites → Terminal** in the desktop manager.

1. Type `vivado` at the command prompt and hit enter

    ![](../imgs/vivado_launch.png)
 
    The Vivado GUI start and show the following screen:

    ![](../imgs/vivado_startup.png)
 
## Step 2: Load sample project

Next, load a sample workload using one of the included example projects:

1. Go to the **Quick Start** section and select **Open Project**.
1. Navigate to `/projects/mfg405/`, select the `project_1.xpr` file, and click **OK**.
1. Double-click on **Open Block Diagram** under **IP INTEGRATOR** in the left-side navigation panel.

    After the design opens you should see this:

    ![](../imgs/vivado_example_project_1.png)
 
    You can now click around the GUI and scroll and pan through the schematics to get a sense of the remote desktop experience.

1. For extra credit, double-click on **Open Synthesized Design** in the navigation panel to see a more complext layout of the design.

You've completed this lab. Click **Next**.
