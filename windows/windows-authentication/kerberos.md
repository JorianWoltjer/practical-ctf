---
description: >-
  The newest Active Directory authentication protocol with less flaws than
  NetNTLM, but still some possible attacks
---

# Kerberos

## Description

To authenticate and authorize you as a user in Active Directory, the Kerberos is the main protocol used in most environments. By issuing tickets with encrypted and signed data you can prove you are who you say you are, or that you should have access to a certain service.&#x20;

While this complex protocol is the successor to [ntlm.md](ntlm.md "mention"), it still has some viable attacks that allow password cracking on some accounts, passing tickets without a password for others, and creating backdoors when access is granted once.&#x20;

#### Terms

* **AS**: **A**uthentication **S**erver = the server to authenticate you as an AD user
* **TGS**: **T**icket **G**ranting **S**ervice = the server granting you a TGT after authenticating
* **KDC**: **K**ey **D**istribution **C**enter = combination of AS and TGS as the main Kerberos peer
* **TGT**: **T**icket **G**ranting **T**icket = the generic ticket to request specific service tickets with
* **ST**: **S**ervice **T**icket (sometimes incorrectly named TGS) = the ticket to authenticate with a specific service
* **AP**: **A**pplication **S**erver = where the user wants to authenticate to

### Authentication Flow

When Kerberos is used for authentication, the following process happens ([source - munra](https://tryhackme.com/room/winadbasics)):

1. The user sends their username and a timestamp encrypted using a key derived from their password to the **Key Distribution Center (KDC)**, a service usually installed on the Domain Controller in charge of creating Kerberos tickets on the network
2. The KDC will create and send back a **Ticket Granting Ticket (TGT)**, allowing the user to request additional tickets to access specific services. The need for a ticket to get more tickets may sound a bit weird, but it allows users to request service tickets without passing their credentials every time they want to connect to a service. Along with the TGT, a **Session Key** is given to the user, which they will need to generate the following requests. \
   \
   Notice the TGT is encrypted using the `krbtgt` account's password hash, and therefore the user can't access its contents. It is essential to know that the encrypted TGT includes a copy of the Session Key as part of its contents, and the KDC does not need to store the Session Key as it can recover a copy by decrypting the TGT if needed

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption><p>Requesting a TGT, and receiving a TGT together with a Session Key</p></figcaption></figure>

3. When a user wants to connect to a service on the network like a share, website, or database, they will use their TGT to ask the KDC for a **Ticket Granting Service (TGS)**. TGS are tickets that allow connection only to the specific service they were created for. To request a TGS, the user will send their username and a timestamp encrypted using the Session Key, along with the TGT and a **Service Principal Name (SPN),** which indicates the service and server name we intend to access
4. As a result, the KDC will send us a TGS along with a **Service Session Key**, which we will need to authenticate to the service we want to access. The TGS is encrypted using a key derived from the **Service Owner Hash**. The Service Owner is the user or machine account that the service runs under. The TGS contains a copy of the Service Session Key on its encrypted contents so that the Service Owner can access it by decrypting the TGS

<figure><img src="../../.gitbook/assets/image (1) (5).png" alt=""><figcaption><p>Requesting a TGS using a TGT, and receiving a TGS together with a Service Session Key</p></figcaption></figure>

5. The TGS can then be sent to the desired service to authenticate and establish a connection. The service will use its configured account's password hash to decrypt the TGS and validate the Service Session Key

<figure><img src="../../.gitbook/assets/image (17).png" alt=""><figcaption><p>Authenticating to a Service using the TGS</p></figcaption></figure>

To summarize, you request a **TGT** and receive a TGT with encrypted data. Then you use this TGT to request a **TGS** for a specific service you want to authenticate with. Finally, you use this TGS to **authenticate** with the service and prove who you are.&#x20;

This is a pretty complex system, and as with most things, there are some attacks on the protocol that can allow an attacker to have more access than they should have, and escalate privileges.

## Protocol Attacks

Check out [#kerberoasting](../lateral-movement.md#kerberoasting "mention") and [#asreproasting](../lateral-movement.md#asreproasting "mention") for some practical attacks against this protocol.
