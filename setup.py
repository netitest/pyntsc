from setuptools import setup, find_packages
   
setup(
    name="pyntsc",
    version="25.06.12.5118",
    author="Beijing Netitest Technology Co., Ltd.",
    author_email="hfli@netitest.com",
    description="Python Object-Oriented Library to Automate Netitest Network Testing Instruments",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "": ["ntsc/*"],
    },
    install_requires=[
        "requests", 
        "ipaddress",
    ],
    python_requires=">=3.6",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    keywords="netitest,supernova,darkbird,jmeter,ddos,ntsc,pyntsc,keysight,ixia,ixnetwork,ixload,spirent,testcenter,stc,avalanche,trex,xena,l2l3,l4l7,l27,tg,traffic generator,test automation,automation api",   
)   

