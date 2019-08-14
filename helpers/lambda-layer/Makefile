TARGET = python/lib/python3.7/site-packages

zat = zsec-aws-tools @ git+https://github.com/zuoralabs/zsec-aws-tools.git@v0.1.3

all: My-Python37-ZAT.zip

My-Python37-ZAT.zip: python
	zip -r My-Python37-ZAT.zip .

python:
	mkdir -p $(TARGET)
	# don't need to install boto3 because it's included by Amazon
	pip install --upgrade --isolated -I --target=$(TARGET) toolz
	pip install --upgrade --isolated -I --target=$(TARGET) --no-deps "$(zat)"

clean:
	rm My-Python37-ZAT.zip
	rm -r python
