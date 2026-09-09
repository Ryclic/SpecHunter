To use CHIA cluster’s automatic provisioning of GCP nodes with chia up, you will need to login to this account and specify this project in the shell from which you bring up your cluster.
pip install google-cloud-compute # In a python Venv
# Can also be installed with system package manager
                      
gcloud auth application-default login                    
gcloud auth application-default set-quota-project <project>  
gcloud services enable compute.googleapis.com --project <project>


You can specify ssh credentials for the instances you create in your cluster configuration yaml for your CHIA workflow. The public key you specify will be included on the instance as an authorized key, and the path to the private key you specify will be used in the ssh commands used to set up logical CHIA workers on the instance. If you only specify the private key file, CHIA can compute the public key and put it in the authorized key list on the instance. You should add this key to your ssh agent before running chia up to make sure it does not prompt you for the passphrase for your ssh key. 

We recommend using Tailscale to create clusters of machines spanning local and GCP compute. See this example here: https://github.com/ucb-bar/chia/tree/main/examples/tailscale where the fully managed cluster yaml shows the fastest way to get started. There is also information in the docs here: https://docs.chialoops.ai/en/latest/user_guides/cluster_config_reference.html#tailnet-tailscale-clusters. You can use Tailscale for free, and you can create an account here: https://tailscale.com/



See https://docs.chialoops.ai/en/latest/user_guides/google_auth.html for using your GCP account to use Gemini in CHIA. 
Additionally, CHIA’s memcpy and circt_issue_solver examples have been augmented with both Antigravity and Gemini in OpenCode, so these can be used as examples: https://github.com/ucb-bar/chia/tree/main/examples/memcpy https://github.com/ucb-bar/chia/tree/main/examples/circt_issue_solver
