#!/bin/bash

docker build -f kmesh.dockerfile -t kmesh:basic ./kmesh

image_id=$(docker images -q kmesh:basic)

container_id=$(docker run -itd --privileged=true -v /usr/src:/usr/src -v /usr/include/linux/bpf.h:/kmesh/config/linux-bpf.h -v /etc/cni/net.d:/etc/cni/net.d -v /opt/cni/bin:/opt/cni/bin -v /mnt:/mnt -v /sys/fs/bpf:/sys/fs/bpf -v /lib/modules:/lib/modules --name kmesh-build kmesh:basic)

merged_id=$(docker inspect $container_id | grep -oP '(?<="MergedDir": ")[^"]*' | cut -d '/' -f 6)

key="kmeshcut"

current_path="/var/lib/docker/overlay2/$merged_id/merged"

cut_cid=$(docker run -itd --name kmesh-cut $image_id)

start_time=$(date +%s.%N)

function apply_audit_rule() {
    echo "Applying audit rule..."
    local path=$1
    local key=$2
    auditctl -D
    auditctl -w "$path/usr" -k "$key"
    rm -rf /var/log/audit/*
}

function install_required_packages() {
	echo "Install required packages..."
	local cid=$1
    docker exec "$cid" yum install -y kmod util-linux make golang clang llvm libboundscheck protobuf-c-devel bpftool libbpf libbpf-devel cmake
}

function start_kmesh() {
    echo "Starting kmesh with a timeout of 1.5 minutes"
    timeout 1.5m docker exec $container_id ./start_kmesh.sh -enable-kmesh -enable-ads=false
    if [ $? -eq 124 ]; then
    	echo "The command timed out"
	else
    	echo "The command completed within the timeout period"
	fi
}

function process_audit_logs() {
	echo "Process audit logs..."
    local key=$1
    ausearch -k "$key" > "$current_path/log"
}

function process_log_files() {
    echo "Processing log files... ($1, $2)"

    local log_file="$1"
    local output_file="$2"
    docker exec "$container_id" sh -c "$(declare -f get_file); get_file '$log_file' '$output_file'"
    echo "Log files processed successfully."
}

function create_whitelist() {
    echo "Creating whitelist... ($1, $2)"
    local input_file="$1"
    local output_file="$2"
    docker exec "$container_id" sh -c "$(declare -f get_linkfile); get_linkfile '$input_file' '$output_file' '$container_id'"
    echo "Whitelist created successfully."
}

function process_blacklist_and_result_for_cut() {
    echo "process_blacklist_and_result_for_cut..."
    docker exec "$container_id" sh -c "$(declare -f get_blacklist); get_blacklist /kmesh/filelist /blacklist"
    docker exec "$container_id" sh -c "(grep -vFf /whitelist /blacklist > /kmesh/result)"
    docker exec "$container_id" sh -c "(grep -vE '/usr/bin/protoc|/usr/lib64/libgomp.so|/usr/lib/golang/src/go/constant|/usr/lib/golang/src/unsafe' /kmesh/result > /kmesh/result.tmp)"
    docker exec "$container_id" sh -c "(mv /kmesh/result.tmp /kmesh/result)"
    echo "process_blacklist_and_result_for_cut completed successfully."
}


function prepare_new_container_env_and_del() {
	echo "Prepare new container env and del..."
    docker cp "$current_path/kmesh/result" "$cut_cid:/kmesh"
	install_required_packages "$cut_cid"
    docker exec "$cut_cid" sh -c "$(declare -f del); $(declare -f is_in_specified_directory); del /kmesh/result"
}

function commit_changes_to_container() {
    cd /root
    docker commit "$cut_cid" kmesh:latesst
}

function calculate_runtime() {
    end_time=$(date +%s.%N)
    runtime=$(echo "$end_time - $start_time" | bc)
    echo "脚本运行时间： $runtime 秒"
}

function get_linkfile() {
	echo "get_linkfile"
    local input_file=$1
	local output_file=$2
	local container_id=$3
	local dir="/kmesh"
	
	nececmd=(
    	"/usr/bin/xargs"
    	"/usr/bin/protoc-c"
    	"/usr/bin/llvm-strip"
	)

    for line in "${nececmd[@]}"; do
    	ldd -r "$line" >> "$input_file.tmp"
    	echo "$line" >> "$input_file"
	done

    while read line; do
  		match=$(echo $line | grep -oP '(?<=\=\> ).*(?=\()')
  		echo $match >> "$input_file.tmp1"
	done < "$input_file.tmp"

	sed -i '/^$/d' "$input_file.tmp1"
	mv "$input_file.tmp1" "$input_file.tmp"
    
    cat "$input_file.tmp" >> "$input_file"

    while read -r line; do
		echo "$line" >> "$output_file"
		readlink -f "$line" >> "$output_file"
    done < "$input_file"

    awk '!seen[$0]++' "$output_file" > "$output_file.tmp"
    mv "$output_file.tmp" "$output_file"
}


function is_in_specified_directory() {
	local file_path=$1

	check_directories=("/usr/src" "/kmesh/config" "/etc/cni/net.d" "/opt/cni/bin" "/mnt" "/sys/fs/bpf" "/usr/lib/modules" "/usr/lib/golang/src/go/types/" "/usr/lib/golang/src" "/usr/share/cmake" "/usr/include" "include")

	for dir in "${check_directories[@]}"; do
		if [[ $file_path == *$dir* ]]; then
			return 0
		fi
	done

	return 1
}

function del() {
	echo "del>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	local input_file=$1

	while read -r file_path; do
  		is_in_specified_directory "$file_path"
  		is_in_specified=$?
  		if [[ $is_in_specified -ne 0 ]]; then
    		rm "$file_path" >> /dev/null 2>&1
  		fi
	done < "$input_file"
	rm -rf /var/cache/*
}


function get_file() {
	echo "get_file"
    local input_file=$1
	local output_file=$2

    grep -o 'name="/[^"]*"' "$input_file" > "$input_file.tmp"
    awk '!seen[$0]++' "$input_file.tmp" > "$input_file.tmp1"
    mv "$input_file.tmp1" "$input_file.tmp"

    awk -F'"' '{print $2}' "$input_file.tmp" > "$output_file"

    while read -r line; do
    	if [ ! -d "$line" ]; then
        	echo "$line" >> "$output_file.tmp"
        fi
    done < "$output_file"
    mv "$output_file.tmp" "$output_file"
}

function get_blacklist() {
	echo "get_blacklist"
	local input_file=$1
	local output_file=$2

	while read -r line; do
  		rpm -ql "$line" >> "$input_file.allfiles"
	done < "$input_file"

	awk '!seen[$0]++' "$input_file.allfiles" > "$input_file.allfilestmp"
	mv "$input_file.allfilestmp" "$input_file.allfiles"

	while read -r line; do
  		if [ ! -d "$line" ]; then
    		echo "$line" >> "$input_file.allfilestmp"
  		fi
	done < "$input_file.allfiles"

	mv "$input_file.allfilestmp" "$input_file.allfiles"

	while read -r line; do
  		readlink -f "$line" >> "$output_file"
	done < "$input_file.allfiles"
}

function main {
	apply_audit_rule "$current_path" "$key"

	install_required_packages "$container_id"

	start_kmesh

	process_audit_logs "$key"

	process_log_files "/log" "/files"

	create_whitelist "/files" "/whitelist"

	process_blacklist_and_result_for_cut

	prepare_new_container_env_and_del

	commit_changes_to_container

	calculate_runtime

}

main


