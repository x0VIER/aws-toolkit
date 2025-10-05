#!/bin/bash
#
# AWS Resource Cleanup Script
# 
# Identifies and optionally removes unused AWS resources to reduce costs.
# Supports EBS volumes, Elastic IPs, Load Balancers, and more.
#
# Author: V Vier
#

# Text formatting
BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

# Default values
DRY_RUN=true
RESOURCE_TYPE=""
REGION=""
PROFILE=""
OLDER_THAN=""
FORCE=false

# Display script usage
function show_usage {
    echo -e "${BOLD}Usage:${RESET} $0 [options]"
    echo
    echo "Options:"
    echo "  --resource-type TYPE   Resource type to clean up (ebs, eip, elb, snapshots, amis, sg)"
    echo "  --region REGION        AWS region to target (default: all regions)"
    echo "  --profile PROFILE      AWS profile to use"
    echo "  --older-than PERIOD    Only consider resources older than this period (e.g., 30d, 6m, 1y)"
    echo "  --dry-run              List resources without deleting (default)"
    echo "  --force                Skip confirmation prompt when deleting resources"
    echo "  --help                 Display this help message"
    echo
    echo "Resource Types:"
    echo "  ebs        - Unattached EBS volumes"
    echo "  eip        - Unassociated Elastic IPs"
    echo "  elb        - Load balancers with no instances"
    echo "  snapshots  - EBS snapshots older than specified period"
    echo "  amis       - Unused AMIs older than specified period"
    echo "  sg         - Security groups not associated with any instances"
    echo "  all        - All resource types"
    echo
    echo "Examples:"
    echo "  $0 --resource-type ebs --dry-run"
    echo "  $0 --resource-type snapshots --older-than 90d --region us-east-1"
    echo "  $0 --resource-type all --profile production"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --resource-type)
            RESOURCE_TYPE="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --older-than)
            OLDER_THAN="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --no-dry-run)
            DRY_RUN=false
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${RESET}"
            show_usage
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$RESOURCE_TYPE" ]]; then
    echo -e "${RED}Error: --resource-type is required${RESET}"
    show_usage
    exit 1
fi

# Build AWS CLI command prefix
AWS_CMD="aws"
if [[ -n "$PROFILE" ]]; then
    AWS_CMD="$AWS_CMD --profile $PROFILE"
fi

# Get list of regions if not specified
if [[ -z "$REGION" ]]; then
    echo -e "${BLUE}No region specified, getting list of enabled regions...${RESET}"
    REGIONS=$($AWS_CMD ec2 describe-regions --query 'Regions[].RegionName' --output text)
else
    REGIONS="$REGION"
fi

# Convert time period to days
function period_to_days {
    local period="$1"
    local number=$(echo "$period" | sed 's/[a-zA-Z]//g')
    local unit=$(echo "$period" | sed 's/[0-9]//g')
    
    case "$unit" in
        d)
            echo "$number"
            ;;
        w)
            echo $((number * 7))
            ;;
        m)
            echo $((number * 30))
            ;;
        y)
            echo $((number * 365))
            ;;
        *)
            echo -e "${RED}Error: Invalid time period format. Use d (days), w (weeks), m (months), or y (years).${RESET}"
            exit 1
            ;;
    esac
}

# Get date from days ago
function days_ago {
    local days="$1"
    date -d "$days days ago" +%Y-%m-%d
}

# Find and clean up unattached EBS volumes
function cleanup_ebs_volumes {
    local region="$1"
    echo -e "${BLUE}Looking for unattached EBS volumes in $region...${RESET}"
    
    # Get list of unattached volumes
    local volumes=$($AWS_CMD ec2 describe-volumes \
        --region "$region" \
        --filters Name=status,Values=available \
        --query 'Volumes[].{ID:VolumeId,Size:Size,Type:VolumeType,Created:CreateTime}' \
        --output json)
    
    # Check if any volumes were found
    local count=$(echo "$volumes" | jq length)
    if [[ $count -eq 0 ]]; then
        echo -e "${GREEN}No unattached EBS volumes found in $region.${RESET}"
        return
    fi
    
    # Filter by age if specified
    if [[ -n "$OLDER_THAN" ]]; then
        local days=$(period_to_days "$OLDER_THAN")
        local cutoff_date=$(days_ago "$days")
        echo -e "${YELLOW}Filtering for volumes older than $cutoff_date${RESET}"
        volumes=$(echo "$volumes" | jq --arg date "$cutoff_date" '[.[] | select(.Created < $date)]')
        count=$(echo "$volumes" | jq length)
        if [[ $count -eq 0 ]]; then
            echo -e "${GREEN}No unattached EBS volumes older than $OLDER_THAN found in $region.${RESET}"
            return
        fi
    fi
    
    # Display volumes
    echo -e "${YELLOW}Found $count unattached EBS volume(s) in $region:${RESET}"
    echo "$volumes" | jq -r '.[] | "ID: \(.ID), Size: \(.Size)GB, Type: \(.Type), Created: \(.Created)"'
    
    # Delete volumes if not in dry run mode
    if [[ "$DRY_RUN" == "false" ]]; then
        if [[ "$FORCE" == "false" ]]; then
            read -p "Are you sure you want to delete these volumes? (y/N) " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                echo -e "${YELLOW}Skipping deletion.${RESET}"
                return
            fi
        fi
        
        echo -e "${YELLOW}Deleting unattached EBS volumes...${RESET}"
        for volume_id in $(echo "$volumes" | jq -r '.[].ID'); do
            echo -e "Deleting volume $volume_id..."
            $AWS_CMD ec2 delete-volume --region "$region" --volume-id "$volume_id"
            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}Successfully deleted volume $volume_id${RESET}"
            else
                echo -e "${RED}Failed to delete volume $volume_id${RESET}"
            fi
        done
    else
        echo -e "${YELLOW}Dry run mode enabled. No volumes will be deleted.${RESET}"
    fi
}

# Find and clean up unassociated Elastic IPs
function cleanup_elastic_ips {
    local region="$1"
    echo -e "${BLUE}Looking for unassociated Elastic IPs in $region...${RESET}"
    
    # Get list of unassociated Elastic IPs
    local eips=$($AWS_CMD ec2 describe-addresses \
        --region "$region" \
        --query 'Addresses[?AssociationId==null].[AllocationId,PublicIp]' \
        --output json)
    
    # Check if any Elastic IPs were found
    local count=$(echo "$eips" | jq length)
    if [[ $count -eq 0 ]]; then
        echo -e "${GREEN}No unassociated Elastic IPs found in $region.${RESET}"
        return
    fi
    
    # Display Elastic IPs
    echo -e "${YELLOW}Found $count unassociated Elastic IP(s) in $region:${RESET}"
    echo "$eips" | jq -r '.[] | "Allocation ID: \(.[0]), Public IP: \(.[1])"'
    
    # Release Elastic IPs if not in dry run mode
    if [[ "$DRY_RUN" == "false" ]]; then
        if [[ "$FORCE" == "false" ]]; then
            read -p "Are you sure you want to release these Elastic IPs? (y/N) " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                echo -e "${YELLOW}Skipping release.${RESET}"
                return
            fi
        fi
        
        echo -e "${YELLOW}Releasing unassociated Elastic IPs...${RESET}"
        for allocation_id in $(echo "$eips" | jq -r '.[][0]'); do
            echo -e "Releasing Elastic IP with allocation ID $allocation_id..."
            $AWS_CMD ec2 release-address --region "$region" --allocation-id "$allocation_id"
            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}Successfully released Elastic IP with allocation ID $allocation_id${RESET}"
            else
                echo -e "${RED}Failed to release Elastic IP with allocation ID $allocation_id${RESET}"
            fi
        done
    else
        echo -e "${YELLOW}Dry run mode enabled. No Elastic IPs will be released.${RESET}"
    fi
}

# Find and clean up load balancers with no instances
function cleanup_load_balancers {
    local region="$1"
    echo -e "${BLUE}Looking for load balancers with no instances in $region...${RESET}"
    
    # Get list of Classic Load Balancers with no instances
    local elbs=$($AWS_CMD elb describe-load-balancers \
        --region "$region" \
        --query 'LoadBalancerDescriptions[?Instances==[]].[LoadBalancerName,CreatedTime]' \
        --output json)
    
    # Check if any Classic Load Balancers were found
    local elb_count=$(echo "$elbs" | jq length)
    
    # Get list of Application and Network Load Balancers with no target groups
    local elbv2s=$($AWS_CMD elbv2 describe-load-balancers \
        --region "$region" \
        --query 'LoadBalancers[].{Name:LoadBalancerName,ARN:LoadBalancerArn,Created:CreatedTime}' \
        --output json)
    
    # Filter ALBs/NLBs with no target groups or empty target groups
    local empty_elbv2s="[]"
    if [[ $(echo "$elbv2s" | jq length) -gt 0 ]]; then
        for lb_arn in $(echo "$elbv2s" | jq -r '.[].ARN'); do
            # Get target groups for this load balancer
            local target_groups=$($AWS_CMD elbv2 describe-target-groups \
                --region "$region" \
                --load-balancer-arn "$lb_arn" \
                --query 'TargetGroups[].TargetGroupArn' \
                --output json)
            
            local has_targets=false
            if [[ $(echo "$target_groups" | jq length) -gt 0 ]]; then
                for tg_arn in $(echo "$target_groups" | jq -r '.[]'); do
                    # Check if target group has targets
                    local targets=$($AWS_CMD elbv2 describe-target-health \
                        --region "$region" \
                        --target-group-arn "$tg_arn" \
                        --query 'TargetHealthDescriptions' \
                        --output json)
                    
                    if [[ $(echo "$targets" | jq length) -gt 0 ]]; then
                        has_targets=true
                        break
                    fi
                done
            fi
            
            if [[ "$has_targets" == "false" ]]; then
                # Add this load balancer to the list of empty ones
                local lb_info=$(echo "$elbv2s" | jq --arg arn "$lb_arn" '.[] | select(.ARN==$arn)')
                empty_elbv2s=$(echo "$empty_elbv2s" | jq --argjson lb "$lb_info" '. += [$lb]')
            fi
        done
    fi
    
    local elbv2_count=$(echo "$empty_elbv2s" | jq length)
    local total_count=$((elb_count + elbv2_count))
    
    if [[ $total_count -eq 0 ]]; then
        echo -e "${GREEN}No load balancers with no instances found in $region.${RESET}"
        return
    fi
    
    # Display load balancers
    echo -e "${YELLOW}Found $total_count load balancer(s) with no instances in $region:${RESET}"
    
    if [[ $elb_count -gt 0 ]]; then
        echo -e "${BOLD}Classic Load Balancers:${RESET}"
        echo "$elbs" | jq -r '.[] | "Name: \(.[0]), Created: \(.[1])"'
    fi
    
    if [[ $elbv2_count -gt 0 ]]; then
        echo -e "${BOLD}Application/Network Load Balancers:${RESET}"
        echo "$empty_elbv2s" | jq -r '.[] | "Name: \(.Name), Created: \(.Created)"'
    fi
    
    # Delete load balancers if not in dry run mode
    if [[ "$DRY_RUN" == "false" ]]; then
        if [[ "$FORCE" == "false" ]]; then
            read -p "Are you sure you want to delete these load balancers? (y/N) " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                echo -e "${YELLOW}Skipping deletion.${RESET}"
                return
            fi
        fi
        
        if [[ $elb_count -gt 0 ]]; then
            echo -e "${YELLOW}Deleting Classic Load Balancers...${RESET}"
            for elb_name in $(echo "$elbs" | jq -r '.[][0]'); do
                echo -e "Deleting Classic Load Balancer $elb_name..."
                $AWS_CMD elb delete-load-balancer --region "$region" --load-balancer-name "$elb_name"
                if [[ $? -eq 0 ]]; then
                    echo -e "${GREEN}Successfully deleted Classic Load Balancer $elb_name${RESET}"
                else
                    echo -e "${RED}Failed to delete Classic Load Balancer $elb_name${RESET}"
                fi
            done
        fi
        
        if [[ $elbv2_count -gt 0 ]]; then
            echo -e "${YELLOW}Deleting Application/Network Load Balancers...${RESET}"
            for lb_arn in $(echo "$empty_elbv2s" | jq -r '.[].ARN'); do
                echo -e "Deleting Load Balancer with ARN $lb_arn..."
                $AWS_CMD elbv2 delete-load-balancer --region "$region" --load-balancer-arn "$lb_arn"
                if [[ $? -eq 0 ]]; then
                    echo -e "${GREEN}Successfully deleted Load Balancer with ARN $lb_arn${RESET}"
                else
                    echo -e "${RED}Failed to delete Load Balancer with ARN $lb_arn${RESET}"
                fi
            done
        fi
    else
        echo -e "${YELLOW}Dry run mode enabled. No load balancers will be deleted.${RESET}"
    fi
}

# Find and clean up old EBS snapshots
function cleanup_snapshots {
    local region="$1"
    echo -e "${BLUE}Looking for old EBS snapshots in $region...${RESET}"
    
    # Check if age filter is specified
    if [[ -z "$OLDER_THAN" ]]; then
        echo -e "${RED}Error: --older-than is required for snapshot cleanup${RESET}"
        return
    fi
    
    local days=$(period_to_days "$OLDER_THAN")
    local cutoff_date=$(days_ago "$days")
    
    echo -e "${YELLOW}Finding snapshots older than $cutoff_date${RESET}"
    
    # Get list of snapshots owned by the current account
    local snapshots=$($AWS_CMD ec2 describe-snapshots \
        --region "$region" \
        --owner-ids self \
        --query "Snapshots[?StartTime<='$cutoff_date'].{ID:SnapshotId,VolumeID:VolumeId,Size:VolumeSize,Created:StartTime,Description:Description}" \
        --output json)
    
    # Check if any snapshots were found
    local count=$(echo "$snapshots" | jq length)
    if [[ $count -eq 0 ]]; then
        echo -e "${GREEN}No snapshots older than $OLDER_THAN found in $region.${RESET}"
        return
    fi
    
    # Display snapshots
    echo -e "${YELLOW}Found $count snapshot(s) older than $OLDER_THAN in $region:${RESET}"
    echo "$snapshots" | jq -r '.[] | "ID: \(.ID), Volume: \(.VolumeID), Size: \(.Size)GB, Created: \(.Created), Description: \(.Description)"'
    
    # Delete snapshots if not in dry run mode
    if [[ "$DRY_RUN" == "false" ]]; then
        if [[ "$FORCE" == "false" ]]; then
            read -p "Are you sure you want to delete these snapshots? (y/N) " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                echo -e "${YELLOW}Skipping deletion.${RESET}"
                return
            fi
        fi
        
        echo -e "${YELLOW}Deleting old snapshots...${RESET}"
        for snapshot_id in $(echo "$snapshots" | jq -r '.[].ID'); do
            echo -e "Deleting snapshot $snapshot_id..."
            $AWS_CMD ec2 delete-snapshot --region "$region" --snapshot-id "$snapshot_id"
            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}Successfully deleted snapshot $snapshot_id${RESET}"
            else
                echo -e "${RED}Failed to delete snapshot $snapshot_id${RESET}"
            fi
        done
    else
        echo -e "${YELLOW}Dry run mode enabled. No snapshots will be deleted.${RESET}"
    fi
}

# Find and clean up unused AMIs
function cleanup_amis {
    local region="$1"
    echo -e "${BLUE}Looking for unused AMIs in $region...${RESET}"
    
    # Check if age filter is specified
    if [[ -z "$OLDER_THAN" ]]; then
        echo -e "${RED}Error: --older-than is required for AMI cleanup${RESET}"
        return
    fi
    
    local days=$(period_to_days "$OLDER_THAN")
    local cutoff_date=$(days_ago "$days")
    
    echo -e "${YELLOW}Finding AMIs older than $cutoff_date${RESET}"
    
    # Get list of AMIs owned by the current account
    local amis=$($AWS_CMD ec2 describe-images \
        --region "$region" \
        --owners self \
        --query "Images[?CreationDate<='$cutoff_date'].{ID:ImageId,Name:Name,Created:CreationDate}" \
        --output json)
    
    # Check if any AMIs were found
    local count=$(echo "$amis" | jq length)
    if [[ $count -eq 0 ]]; then
        echo -e "${GREEN}No AMIs older than $OLDER_THAN found in $region.${RESET}"
        return
    fi
    
    # Get list of running instances
    local instances=$($AWS_CMD ec2 describe-instances \
        --region "$region" \
        --query 'Reservations[].Instances[].ImageId' \
        --output json)
    
    # Filter out AMIs that are in use
    local unused_amis=$(echo "$amis" | jq --argjson instances "$instances" '[.[] | select(.ID as $id | $instances | index($id) | not)]')
    local unused_count=$(echo "$unused_amis" | jq length)
    
    if [[ $unused_count -eq 0 ]]; then
        echo -e "${GREEN}No unused AMIs older than $OLDER_THAN found in $region.${RESET}"
        return
    fi
    
    # Display AMIs
    echo -e "${YELLOW}Found $unused_count unused AMI(s) older than $OLDER_THAN in $region:${RESET}"
    echo "$unused_amis" | jq -r '.[] | "ID: \(.ID), Name: \(.Name), Created: \(.Created)"'
    
    # Delete AMIs if not in dry run mode
    if [[ "$DRY_RUN" == "false" ]]; then
        if [[ "$FORCE" == "false" ]]; then
            read -p "Are you sure you want to deregister these AMIs? (y/N) " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                echo -e "${YELLOW}Skipping deregistration.${RESET}"
                return
            fi
        fi
        
        echo -e "${YELLOW}Deregistering unused AMIs...${RESET}"
        for ami_id in $(echo "$unused_amis" | jq -r '.[].ID'); do
            # Get associated snapshots
            local snapshots=$($AWS_CMD ec2 describe-images \
                --region "$region" \
                --image-ids "$ami_id" \
                --query 'Images[].BlockDeviceMappings[].Ebs.SnapshotId' \
                --output json)
            
            # Deregister AMI
            echo -e "Deregistering AMI $ami_id..."
            $AWS_CMD ec2 deregister-image --region "$region" --image-id "$ami_id"
            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}Successfully deregistered AMI $ami_id${RESET}"
                
                # Delete associated snapshots
                for snapshot_id in $(echo "$snapshots" | jq -r '.[]'); do
                    echo -e "Deleting associated snapshot $snapshot_id..."
                    $AWS_CMD ec2 delete-snapshot --region "$region" --snapshot-id "$snapshot_id"
                    if [[ $? -eq 0 ]]; then
                        echo -e "${GREEN}Successfully deleted snapshot $snapshot_id${RESET}"
                    else
                        echo -e "${RED}Failed to delete snapshot $snapshot_id${RESET}"
                    fi
                done
            else
                echo -e "${RED}Failed to deregister AMI $ami_id${RESET}"
            fi
        done
    else
        echo -e "${YELLOW}Dry run mode enabled. No AMIs will be deregistered.${RESET}"
    fi
}

# Find and clean up unused security groups
function cleanup_security_groups {
    local region="$1"
    echo -e "${BLUE}Looking for unused security groups in $region...${RESET}"
    
    # Get list of all security groups
    local all_sgs=$($AWS_CMD ec2 describe-security-groups \
        --region "$region" \
        --query 'SecurityGroups[].{ID:GroupId,Name:GroupName,Description:Description,VpcId:VpcId}' \
        --output json)
    
    # Get list of security groups in use by EC2 instances
    local instance_sgs=$($AWS_CMD ec2 describe-instances \
        --region "$region" \
        --query 'Reservations[].Instances[].SecurityGroups[].GroupId' \
        --output json)
    
    # Get list of security groups in use by RDS instances
    local rds_sgs=$($AWS_CMD rds describe-db-instances \
        --region "$region" \
        --query 'DBInstances[].VpcSecurityGroups[].VpcSecurityGroupId' \
        --output json 2>/dev/null || echo "[]")
    
    # Get list of security groups in use by ELBs
    local elb_sgs=$($AWS_CMD elb describe-load-balancers \
        --region "$region" \
        --query 'LoadBalancerDescriptions[].SecurityGroups' \
        --output json 2>/dev/null || echo "[]")
    
    # Get list of security groups in use by ALBs/NLBs
    local elbv2_sgs=$($AWS_CMD elbv2 describe-load-balancers \
        --region "$region" \
        --query 'LoadBalancers[].SecurityGroups' \
        --output json 2>/dev/null || echo "[]")
    
    # Get list of security groups in use by Lambda functions
    local lambda_sgs=$($AWS_CMD lambda list-functions \
        --region "$region" \
        --query 'Functions[].VpcConfig.SecurityGroupIds' \
        --output json 2>/dev/null || echo "[]")
    
    # Get list of security groups in use by ElastiCache clusters
    local elasticache_sgs=$($AWS_CMD elasticache describe-cache-clusters \
        --region "$region" \
        --query 'CacheClusters[].SecurityGroups[].SecurityGroupId' \
        --output json 2>/dev/null || echo "[]")
    
    # Combine all security groups in use
    local used_sgs=$(echo "$instance_sgs $rds_sgs $elb_sgs $elbv2_sgs $lambda_sgs $elasticache_sgs" | jq -s 'add | flatten | unique')
    
    # Filter out default security groups and security groups that are in use
    local unused_sgs=$(echo "$all_sgs" | jq --argjson used "$used_sgs" '[.[] | select(.Name != "default" and (.ID as $id | $used | index($id) | not))]')
    local unused_count=$(echo "$unused_sgs" | jq length)
    
    if [[ $unused_count -eq 0 ]]; then
        echo -e "${GREEN}No unused security groups found in $region.${RESET}"
        return
    fi
    
    # Display security groups
    echo -e "${YELLOW}Found $unused_count unused security group(s) in $region:${RESET}"
    echo "$unused_sgs" | jq -r '.[] | "ID: \(.ID), Name: \(.Name), VPC: \(.VpcId), Description: \(.Description)"'
    
    # Delete security groups if not in dry run mode
    if [[ "$DRY_RUN" == "false" ]]; then
        if [[ "$FORCE" == "false" ]]; then
            read -p "Are you sure you want to delete these security groups? (y/N) " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                echo -e "${YELLOW}Skipping deletion.${RESET}"
                return
            fi
        fi
        
        echo -e "${YELLOW}Deleting unused security groups...${RESET}"
        for sg_id in $(echo "$unused_sgs" | jq -r '.[].ID'); do
            echo -e "Deleting security group $sg_id..."
            $AWS_CMD ec2 delete-security-group --region "$region" --group-id "$sg_id"
            if [[ $? -eq 0 ]]; then
                echo -e "${GREEN}Successfully deleted security group $sg_id${RESET}"
            else
                echo -e "${RED}Failed to delete security group $sg_id${RESET}"
            fi
        done
    else
        echo -e "${YELLOW}Dry run mode enabled. No security groups will be deleted.${RESET}"
    fi
}

# Main execution
echo -e "${BOLD}AWS Resource Cleanup Script${RESET}"
echo -e "Mode: $(if [[ "$DRY_RUN" == "true" ]]; then echo "${YELLOW}DRY RUN${RESET}"; else echo "${RED}DELETE${RESET}"; fi)"
echo -e "Resource Type: ${BLUE}$RESOURCE_TYPE${RESET}"
if [[ -n "$REGION" ]]; then
    echo -e "Region: ${BLUE}$REGION${RESET}"
else
    echo -e "Region: ${BLUE}All Regions${RESET}"
fi
if [[ -n "$PROFILE" ]]; then
    echo -e "Profile: ${BLUE}$PROFILE${RESET}"
fi
if [[ -n "$OLDER_THAN" ]]; then
    echo -e "Older Than: ${BLUE}$OLDER_THAN${RESET}"
fi
echo

# Process each region
for region in $REGIONS; do
    echo -e "${BOLD}Processing region: $region${RESET}"
    
    case "$RESOURCE_TYPE" in
        ebs)
            cleanup_ebs_volumes "$region"
            ;;
        eip)
            cleanup_elastic_ips "$region"
            ;;
        elb)
            cleanup_load_balancers "$region"
            ;;
        snapshots)
            cleanup_snapshots "$region"
            ;;
        amis)
            cleanup_amis "$region"
            ;;
        sg)
            cleanup_security_groups "$region"
            ;;
        all)
            cleanup_ebs_volumes "$region"
            cleanup_elastic_ips "$region"
            cleanup_load_balancers "$region"
            if [[ -n "$OLDER_THAN" ]]; then
                cleanup_snapshots "$region"
                cleanup_amis "$region"
            fi
            cleanup_security_groups "$region"
            ;;
        *)
            echo -e "${RED}Error: Unknown resource type: $RESOURCE_TYPE${RESET}"
            show_usage
            exit 1
            ;;
    esac
    
    echo
done

echo -e "${GREEN}Resource cleanup process completed.${RESET}"
