import com.vanniktech.maven.publish.SonatypeHost

plugins {
  java
  id("com.vanniktech.maven.publish") version "0.15.1"
}

tasks.withType<JavaCompile> {
  sourceCompatibility = "1.7"
  targetCompatibility = "1.7"
}

repositories {
  mavenCentral()
}

dependencies {
  testImplementation("junit:junit:4.13.2")
}

mavenPublish {
  sonatypeHost = SonatypeHost.S01
}
