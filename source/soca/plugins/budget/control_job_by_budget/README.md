More Detailed Instructions + Screenshot will be added soon

- Create an AWS Budget

- Create a config file (eg: budget_users.cfg)

Important: Budget name (between [ ]) must exactly match the name of the budget on AWS Budget
```bash
# Budget name  must exactly match the name of the budget specified on AWS Budget

[Budget1 Name on AWS Budget]
user1
user2

[Budget2 Name on AWS Budget]
user3

```
- Copy hook.py on your cluster
- Create a pbs hook at queuejob
```bash
qmgr -c "create hook check_user_budget event=queuejob"
qmgr -c "import hook check_user_budget application/x-python default <PATH_TO_YOUR_HOOK.PY>"
# In case of rollback
qmgr -c "delete hook check_user_budget"
```

- Make sure your username is on the config file

- Try to submit a job

If user does not have a budget, job will be rejected

If user budget exceed allocated budget, job will be rejected

Otherwise, job will be submitted

