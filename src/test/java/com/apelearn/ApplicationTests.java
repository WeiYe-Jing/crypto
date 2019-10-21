package com.apelearn;

import lombok.extern.log4j.Log4j2;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = ApplicationTests.class)
@Log4j2
public class ApplicationTests{

	@Test
	public void contextLoads() {
		log.info("info级别的日志");
		log.warn("warn级别的日志");
		log.error("error级别的日志");
	}
}
