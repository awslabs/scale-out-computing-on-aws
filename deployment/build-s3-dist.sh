#!/bin/bash
#
# This assumes all of the OS-level configuration has been completed and git repo has already been cloned
#
# This script should be run from the repo's deployment directory
# cd deployment
# ./build-s3-dist.sh source-bucket-base-name solution-name version-code
#
# Paramenters:
#  - source-bucket-base-name: Name for the S3 bucket location where the template will source the Lambda
#    code from. The template will append '-[region_name]' to this bucket name.
#    For example: ./build-s3-dist.sh solutions my-solution v1.0.0
#    The template will then expect the source code to be located in the solutions-[region_name] bucket
#
#  - solution-name: name of the solution for consistency
#
#  - version-code: version of the package

# Check to see if input has been provided:
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Please provide the base source bucket name, trademark approved solution name and version where the lambda code will eventually reside."
    echo "For example: ./build-s3-dist.sh solutions trademarked-solution-name v1.0.0"
    exit 1
fi

# Get reference for all important folders
template_dir="$PWD"
template_dist_dir="$template_dir/global-s3-assets"
build_dist_dir="$template_dir/regional-s3-assets"
source_dir="$template_dir/../source"

echo "------------------------------------------------------------------------------"
echo "[Init] Clean old dist, node_modules and bower_components folders"
echo "------------------------------------------------------------------------------"
echo "rm -rf $template_dist_dir"
rm -rf $template_dist_dir
echo "mkdir -p $template_dist_dir"
mkdir -p $template_dist_dir
echo "rm -rf $build_dist_dir"
rm -rf $build_dist_dir
echo "mkdir -p $build_dist_dir"
mkdir -p $build_dist_dir

echo "------------------------------------------------------------------------------"
echo "[Packing] Global Assets"
echo "------------------------------------------------------------------------------"
echo "------------------------------------------------------------------------------"
echo "[Packing] Copy all templates for CfnNagScan and force .template extension"
echo "------------------------------------------------------------------------------"
echo "mkdir -p $template_dist_dir"
mkdir -p $template_dist_dir
echo "cp ../source/scale-out-computing-on-aws.template $template_dist_dir/"
cp ../source/scale-out-computing-on-aws.template $template_dist_dir/
echo "cp ../source/install-with-existing-resources.template $template_dist_dir/"
cp ../source/install-with-existing-resources.template $template_dist_dir/
echo "cp ../source/README.txt $template_dist_dir/"
cp ../source/README.txt $template_dist_dir/


echo "Updating code source bucket in template with $1-reference"
replace="s/%%BUCKET_NAME%%/$1-reference/g"
echo "sed -i '' -e $replace $template_dist_dir/scale-out-computing-on-aws.template"
sed -i '' -e $replace $template_dist_dir/*.template
replace="s/%%SOLUTION_NAME%%/$2/g"
echo "sed -i '' -e $replace $template_dist_dir/scale-out-computing-on-aws.template"
sed -i '' -e $replace $template_dist_dir/*.template
replace="s/%%VERSION%%/$3/g"
echo "sed -i '' -e $replace $template_dist_dir/scale-out-computing-on-aws.template"
sed -i '' -e $replace $template_dist_dir/*.template
echo "cp -r $source_dir/scripts $template_dist_dir"
cp -r $source_dir/scripts $template_dist_dir
echo "cp -r $source_dir/templates $template_dist_dir"
cp -r $source_dir/templates $template_dist_dir

echo "tar -czf $template_dist_dir/soca.tar.gz $source_dir/soca"
cd $source_dir/soca
tar -czf $template_dist_dir/soca.tar.gz *


echo "------------------------------------------------------------------------------"
echo "[Packing] Regional Assets"
echo "------------------------------------------------------------------------------"
echo "cp -r $source_dir/scripts $build_dist_dir"
cp -r $source_dir/scripts $build_dist_dir
echo "cp -r $source_dir/templates $build_dist_dir"
cp -r $source_dir/templates $build_dist_dir
