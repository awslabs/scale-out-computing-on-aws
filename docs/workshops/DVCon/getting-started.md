# Getting Started

To begin, you'll log into a temporary AWS account that will be provided to you for this workshop.

## Accessing your AWS account

At the beginning of the workshop, you will be given a **12-character access code**. This access code grants you access to a temporary AWS account that you'll use for this workshop.

### Step 1. Log in

Go to https://dashboard.eventengine.run, and enter the access code in the **Team Hash** field.  Click **Proceed**.

![Event Engine Login](imgs/ee-login.png)

### Step 2. Get Credentials

1. On the **Team Dashboard**, click **SSH Key** to download the SSH Keypair PEM file.  You'll use this file later to SSH into an EC2 instance.

1. If your using a Mac, change permissions of the PEM file that you just downloaded.  This is an SSH security requirement.

    `chmod 600 /path/to/file.pem`

1. Next, click **AWS Console** to begin the login process to the AWS account.

![Event Engine Dashboard](imgs/ee-team-dashboard.png)

### Step 3. Open AWS Console

Click **Open AWS Console**. For this workshop, you will not need the **Credentials** or **CLI Snippets**

![AWS Console](imgs/ee-open-console.png)

Awesome! Now that you are logged into your temporary AWS account, we can start the labs. Click **Next**.