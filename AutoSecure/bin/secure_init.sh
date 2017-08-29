CMD=`basename $0`
DIR=`dirname $0`

base_dir="${DIR}/../"
lib_dir="${DIR}/../lib"
data_dir="${DIR}/../data"
core_dir="${DIR}/../core"
log_dir="${DIR}/../log"
nessus_dir="${DIR}/../../nessus"

export PYTHONPATH=$PYTHONPATH:$base_dir:$lib_dir:$data_dir:$core_dir:$log_dir:$nessus_dir

cd $core_dir

python auto_secure.py -s 'WebApplicationTests' -d 