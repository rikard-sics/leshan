package org.eclipse.leshan.client.demo;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.leshan.client.resource.BaseInstanceEnabler;
import org.eclipse.leshan.client.servers.ServerIdentity;
import org.eclipse.leshan.core.Destroyable;
import org.eclipse.leshan.core.model.ObjectModel;
import org.eclipse.leshan.core.node.LwM2mResource;
import org.eclipse.leshan.core.response.ExecuteResponse;
import org.eclipse.leshan.core.response.ReadResponse;
import org.eclipse.leshan.core.response.WriteResponse;
import org.eclipse.leshan.core.util.NamedThreadFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyLight extends BaseInstanceEnabler implements Destroyable {

    private static final Logger LOG = LoggerFactory.getLogger(MyLight.class);

    private static final String UNIT_CELSIUS = "cel";
    private static final int LED_STATE = 9700;
    private static final int UNITS = 9701;
    private static final int MAX_MEASURED_VALUE = 9602;
    private static final int TOGGLE_LED = 9601;
    private static final int RESET_MIN_MAX_MEASURED_VALUES = 9605;
    private static final List<Integer> supportedResources = Arrays.asList(LED_STATE, TOGGLE_LED);
    private final ScheduledExecutorService scheduler;
    private final Random rng = new Random();
    private double currentTemp = 20d;
    private double minMeasuredValue = currentTemp;
    private double maxMeasuredValue = currentTemp;
    
    private boolean ledOn = false;

    public MyLight() {
        this.scheduler = Executors.newSingleThreadScheduledExecutor(new NamedThreadFactory("LED Light"));
        scheduler.scheduleAtFixedRate(new Runnable() {

            @Override
            public void run() {
                // adjustTemperature();
            }
        }, 2, 2, TimeUnit.SECONDS);
    }

    @Override
    public synchronized ReadResponse read(ServerIdentity identity, int resourceId) {
        LOG.info("Read on LED resource /{}/{}/{}", getModel().id, getId(), resourceId);
        switch (resourceId) {
        case LED_STATE:
        	if(ledOn) {
        		return ReadResponse.success(resourceId, "Current LED status: On");	
        	} else {
        		return ReadResponse.success(resourceId, "Current LED status: Off");
        	}
        case TOGGLE_LED:
            return ReadResponse.success(resourceId, Boolean.toString(ledOn));
        default:
            return super.read(identity, resourceId);
        }
    }

    @Override
    public WriteResponse write(ServerIdentity identity, boolean replace, int resourceid, LwM2mResource value) {
        LOG.info("Write on Device resource /{}/{}/{}", getModel().id, getId(), resourceid);

        switch (resourceid) {
        case TOGGLE_LED:
        	// System.out.println("Written value: " + (String) value.getValue());
        	String valueStr = ((String) value.getValue()).toLowerCase();
        	if(valueStr.equals("off")) {
        		ledOn = false;
        	} else if(valueStr.equals("on")) {
        		ledOn = true;
        	} else if(valueStr.equals("toggle")) {
        		ledOn = !ledOn;
        	}
        	
        	if(ledOn) {
        		//Run script to turn on
        		System.out.println("Turning on LED.");
				try {
					String command = "python LED-on.py";
					Runtime.getRuntime().exec(command);
				} catch (IOException e) {
					System.err.print("Failed to run python script: ");
					e.printStackTrace();
				}
        	} else {
        		//Run script to turn off
        		System.out.println("Turning off LED.");
				try {
					String command = "python LED-off.py";
					Runtime.getRuntime().exec(command);
				} catch (IOException e) {
					System.err.print("Failed to run python script: ");
					e.printStackTrace();
				}
        	}
        	
        	return WriteResponse.success();
        default:
            return super.write(identity, replace, resourceid, value);
        }
    }
    
    @Override
    public synchronized ExecuteResponse execute(ServerIdentity identity, int resourceId, String params) {
        LOG.info("Execute on LED resource /{}/{}/{}", getModel().id, getId(), resourceId);
        switch (resourceId) {
        case RESET_MIN_MAX_MEASURED_VALUES:
            resetMinMaxMeasuredValues();
            return ExecuteResponse.success();
        default:
            return super.execute(identity, resourceId, params);
        }
    }

    private double getTwoDigitValue(double value) {
        BigDecimal toBeTruncated = BigDecimal.valueOf(value);
        return toBeTruncated.setScale(2, RoundingMode.HALF_UP).doubleValue();
    }

    private void adjustTemperature() {
        float delta = (rng.nextInt(20) - 10) / 10f;
        currentTemp += delta;
        Integer changedResource = adjustMinMaxMeasuredValue(currentTemp);
        if (changedResource != null) {
            fireResourcesChange(LED_STATE, changedResource);
        } else {
            fireResourcesChange(LED_STATE);
        }
    }

    private synchronized Integer adjustMinMaxMeasuredValue(double newTemperature) {
        if (newTemperature > maxMeasuredValue) {
            maxMeasuredValue = newTemperature;
            return MAX_MEASURED_VALUE;
        } else if (newTemperature < minMeasuredValue) {
            minMeasuredValue = newTemperature;
            return TOGGLE_LED;
        } else {
            return null;
        }
    }

    private void resetMinMaxMeasuredValues() {
        minMeasuredValue = currentTemp;
        maxMeasuredValue = currentTemp;
    }

    @Override
    public List<Integer> getAvailableResourceIds(ObjectModel model) {
        return supportedResources;
    }

    @Override
    public void destroy() {
        scheduler.shutdown();
    }
}
